package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"cloak/internal/vault"
)

// OpenAIProvider implements Provider for the OpenAI Chat Completions API.
// Its request/response shape differs from Anthropic's in two places that
// matter here: there's no top-level "system" field (the system prompt is
// just the first message with role "system"), and streaming is flatter -
// one "choices[].delta.content" string per chunk, no separate
// content_block_start/stop events, terminated by a literal "data: [DONE]".
type OpenAIProvider struct{}

func (OpenAIProvider) Name() string { return "openai" }

func (OpenAIProvider) DeriveSessionID(parsed map[string]interface{}) string {
	messages, _ := parsed["messages"].([]interface{})
	h := sha256.New()
	if m := firstMessageWithRole(messages, "system"); m != nil {
		b, _ := json.Marshal(m)
		h.Write(b)
	}
	if m := firstMessageWithRole(messages, "user"); m != nil {
		b, _ := json.Marshal(m)
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func firstMessageWithRole(messages []interface{}, role string) interface{} {
	for _, m := range messages {
		obj, ok := m.(map[string]interface{})
		if !ok {
			continue
		}
		if r, _ := obj["role"].(string); r == role {
			return obj
		}
	}
	return nil
}

// StreamRestore relays an OpenAI SSE stream, restoring placeholders in
// each choice's delta.content and in each streamed tool call's
// delta.tool_calls[].function.arguments, via the same placeholderBuffer
// used for Anthropic. Content is keyed per choice index; tool-call
// arguments are keyed per (choice index, tool call index), since a model
// can stream several parallel tool calls within one choice.
//
// Restoring tool-call arguments matters for more than coverage: a coding
// agent routinely echoes previously-redacted file content back through a
// tool call (e.g. "edit this file and write it back"). Skipping
// restoration there would leave literal "{{...}}" placeholder text in a
// file the agent writes to disk.
//
// Only "data: " lines are expected on the wire here - OpenAI's stream
// doesn't use Server-Sent Events' "event:" field the way Anthropic's
// does - so this rebuilds the blank-line framing itself rather than
// forwarding it.
func (OpenAIProvider) StreamRestore(w http.ResponseWriter, body io.Reader, v *vault.Vault, sessionID string) {
	flusher, _ := w.(http.Flusher)
	scanner := newSSEScanner(body)

	contentBuffers := map[int]*placeholderBuffer{}
	toolCallBuffers := map[int]map[int]*placeholderBuffer{}

	for scanner.Scan() {
		line := scanner.Text()
		payload, ok := strings.CutPrefix(line, "data: ")
		if !ok {
			continue
		}

		if payload == "[DONE]" {
			for idx, buf := range contentBuffers {
				flushOpenAIContentRemainder(w, v, sessionID, idx, buf)
			}
			for choiceIdx, buffers := range toolCallBuffers {
				for tcIdx, buf := range buffers {
					flushOpenAIToolCallRemainder(w, v, sessionID, choiceIdx, tcIdx, buf)
				}
			}
			fmt.Fprint(w, "data: [DONE]\n\n")
			if flusher != nil {
				flusher.Flush()
			}
			continue
		}

		var evt map[string]interface{}
		if err := json.Unmarshal([]byte(payload), &evt); err != nil {
			fmt.Fprintf(w, "data: %s\n\n", payload)
			if flusher != nil {
				flusher.Flush()
			}
			continue
		}

		restoreOpenAIChunk(evt, contentBuffers, toolCallBuffers, v, sessionID)

		out, _ := json.Marshal(evt)
		fmt.Fprintf(w, "data: %s\n\n", out)
		if flusher != nil {
			flusher.Flush()
		}
	}
	logScannerError("openai", scanner.Err())
}

func restoreOpenAIChunk(evt map[string]interface{}, contentBuffers map[int]*placeholderBuffer, toolCallBuffers map[int]map[int]*placeholderBuffer, v *vault.Vault, sessionID string) {
	choices, _ := evt["choices"].([]interface{})
	for _, c := range choices {
		choice, ok := c.(map[string]interface{})
		if !ok {
			continue
		}
		idx := 0
		if f, ok := choice["index"].(float64); ok {
			idx = int(f)
		}

		delta, _ := choice["delta"].(map[string]interface{})
		if delta == nil {
			delta = map[string]interface{}{}
			choice["delta"] = delta
		}

		restoreOpenAIContentDelta(delta, contentBuffers, idx, v, sessionID)
		restoreOpenAIToolCallDeltas(delta, toolCallBuffers, idx, v, sessionID)

		if reason, _ := choice["finish_reason"].(string); reason != "" {
			drainOpenAIContentBuffer(delta, contentBuffers, idx, v, sessionID)
			drainOpenAIToolCallBuffers(delta, toolCallBuffers, idx, v, sessionID)
		}
	}
}

func restoreOpenAIContentDelta(delta map[string]interface{}, buffers map[int]*placeholderBuffer, idx int, v *vault.Vault, sessionID string) {
	content, isText := delta["content"].(string)
	if !isText {
		return
	}
	buf, ok := buffers[idx]
	if !ok {
		buf = &placeholderBuffer{}
		buffers[idx] = buf
	}
	flush := buf.feed(content)
	if sessionID != "" {
		flush = v.Restore(sessionID, flush)
	}
	delta["content"] = flush
}

func drainOpenAIContentBuffer(delta map[string]interface{}, buffers map[int]*placeholderBuffer, idx int, v *vault.Vault, sessionID string) {
	buf, ok := buffers[idx]
	if !ok {
		return
	}
	delete(buffers, idx)
	remainder := buf.drain()
	if remainder == "" {
		return
	}
	if sessionID != "" {
		remainder = v.Restore(sessionID, remainder)
	}
	existing, _ := delta["content"].(string)
	delta["content"] = existing + remainder
}

func restoreOpenAIToolCallDeltas(delta map[string]interface{}, toolCallBuffers map[int]map[int]*placeholderBuffer, choiceIdx int, v *vault.Vault, sessionID string) {
	toolCalls, _ := delta["tool_calls"].([]interface{})
	if len(toolCalls) == 0 {
		return
	}
	buffers := toolCallBuffers[choiceIdx]
	if buffers == nil {
		buffers = map[int]*placeholderBuffer{}
		toolCallBuffers[choiceIdx] = buffers
	}
	for _, tc := range toolCalls {
		call, ok := tc.(map[string]interface{})
		if !ok {
			continue
		}
		tcIdx := 0
		if f, ok := call["index"].(float64); ok {
			tcIdx = int(f)
		}
		fn, _ := call["function"].(map[string]interface{})
		if fn == nil {
			continue
		}
		args, isText := fn["arguments"].(string)
		if !isText {
			continue
		}
		buf, ok := buffers[tcIdx]
		if !ok {
			buf = &placeholderBuffer{}
			buffers[tcIdx] = buf
		}
		flush := buf.feed(args)
		if sessionID != "" {
			flush = v.Restore(sessionID, flush)
		}
		fn["arguments"] = flush
	}
}

func drainOpenAIToolCallBuffers(delta map[string]interface{}, toolCallBuffers map[int]map[int]*placeholderBuffer, choiceIdx int, v *vault.Vault, sessionID string) {
	buffers, ok := toolCallBuffers[choiceIdx]
	if !ok {
		return
	}
	for tcIdx, buf := range buffers {
		remainder := buf.drain()
		if remainder == "" {
			continue
		}
		if sessionID != "" {
			remainder = v.Restore(sessionID, remainder)
		}
		appendToolCallArgumentRemainder(delta, tcIdx, remainder)
	}
	delete(toolCallBuffers, choiceIdx)
}

// appendToolCallArgumentRemainder adds a drained remainder to the
// matching tool_calls entry already in delta, or synthesizes one if the
// finishing chunk didn't carry tool_calls at all (the common case: the
// final chunk usually just carries finish_reason).
func appendToolCallArgumentRemainder(delta map[string]interface{}, tcIdx int, remainder string) {
	toolCalls, _ := delta["tool_calls"].([]interface{})
	for _, tc := range toolCalls {
		call, ok := tc.(map[string]interface{})
		if !ok {
			continue
		}
		if f, ok := call["index"].(float64); ok && int(f) == tcIdx {
			fn, _ := call["function"].(map[string]interface{})
			if fn == nil {
				fn = map[string]interface{}{}
				call["function"] = fn
			}
			existing, _ := fn["arguments"].(string)
			fn["arguments"] = existing + remainder
			return
		}
	}
	delta["tool_calls"] = append(toolCalls, map[string]interface{}{
		"index":    tcIdx,
		"function": map[string]interface{}{"arguments": remainder},
	})
}

func flushOpenAIContentRemainder(w http.ResponseWriter, v *vault.Vault, sessionID string, idx int, buf *placeholderBuffer) {
	remainder := buf.drain()
	if remainder == "" {
		return
	}
	if sessionID != "" {
		remainder = v.Restore(sessionID, remainder)
	}
	evt := map[string]interface{}{
		"choices": []interface{}{
			map[string]interface{}{
				"index": idx,
				"delta": map[string]interface{}{"content": remainder},
			},
		},
	}
	payload, _ := json.Marshal(evt)
	fmt.Fprintf(w, "data: %s\n\n", payload)
}

func flushOpenAIToolCallRemainder(w http.ResponseWriter, v *vault.Vault, sessionID string, choiceIdx, tcIdx int, buf *placeholderBuffer) {
	remainder := buf.drain()
	if remainder == "" {
		return
	}
	if sessionID != "" {
		remainder = v.Restore(sessionID, remainder)
	}
	evt := map[string]interface{}{
		"choices": []interface{}{
			map[string]interface{}{
				"index": choiceIdx,
				"delta": map[string]interface{}{
					"tool_calls": []interface{}{
						map[string]interface{}{
							"index":    tcIdx,
							"function": map[string]interface{}{"arguments": remainder},
						},
					},
				},
			},
		},
	}
	payload, _ := json.Marshal(evt)
	fmt.Fprintf(w, "data: %s\n\n", payload)
}
