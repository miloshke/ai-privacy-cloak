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

// GeminiProvider implements Provider for Google's Generative Language API
// (generateContent / streamGenerateContent?alt=sse). Its shapes differ
// from both other providers: messages are "contents" with role
// "user"/"model" (not "assistant") made of "parts" (not a flat string),
// and the system prompt is a top-level "systemInstruction" object rather
// than a plain string field.
//
// One real difference that simplifies tool-call handling here: a
// functionCall part arrives as a complete object in a single chunk,
// unlike Anthropic's input_json_delta or OpenAI's tool_calls arguments,
// which stream incrementally as partial JSON strings. So functionCall
// args get restored in one pass with the shared redactJSON walker (same
// walker used for request-side redaction, just with a restore callback
// instead of a redact one) - no placeholderBuffer needed there, only for
// the incrementally-streamed "text" parts.
type GeminiProvider struct{}

func (GeminiProvider) Name() string { return "gemini" }

func (GeminiProvider) DeriveSessionID(parsed map[string]interface{}) string {
	h := sha256.New()
	if sysInstr, ok := parsed["systemInstruction"]; ok {
		b, _ := json.Marshal(sysInstr)
		h.Write(b)
	}
	if contents, ok := parsed["contents"].([]interface{}); ok && len(contents) > 0 {
		b, _ := json.Marshal(contents[0])
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// StreamRestore relays a Gemini SSE stream (requested via ?alt=sse),
// restoring placeholders in each candidate's streamed text via the same
// placeholderBuffer used for the other providers, keyed per candidate
// index. Gemini signals the end of a candidate's output with
// finishReason on that candidate's own chunk rather than a separate
// stop event or a [DONE] sentinel, so the buffer drains there.
func (GeminiProvider) StreamRestore(w http.ResponseWriter, body io.Reader, v *vault.Vault, sessionID string) {
	flusher, _ := w.(http.Flusher)
	scanner := newSSEScanner(body)

	textBuffers := map[int]*placeholderBuffer{}

	for scanner.Scan() {
		line := scanner.Text()
		payload, ok := strings.CutPrefix(line, "data: ")
		if !ok {
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

		restoreGeminiChunk(evt, textBuffers, v, sessionID)

		out, _ := json.Marshal(evt)
		fmt.Fprintf(w, "data: %s\n\n", out)
		if flusher != nil {
			flusher.Flush()
		}
	}
	logScannerError("gemini", scanner.Err())
}

func restoreGeminiChunk(evt map[string]interface{}, buffers map[int]*placeholderBuffer, v *vault.Vault, sessionID string) {
	candidates, _ := evt["candidates"].([]interface{})
	for _, c := range candidates {
		cand, ok := c.(map[string]interface{})
		if !ok {
			continue
		}
		idx := 0
		if f, ok := cand["index"].(float64); ok {
			idx = int(f)
		}
		buf, ok := buffers[idx]
		if !ok {
			buf = &placeholderBuffer{}
			buffers[idx] = buf
		}

		content, _ := cand["content"].(map[string]interface{})
		if content == nil {
			content = map[string]interface{}{}
			cand["content"] = content
		}
		parts, _ := content["parts"].([]interface{})

		for _, p := range parts {
			part, ok := p.(map[string]interface{})
			if !ok {
				continue
			}
			if text, isText := part["text"].(string); isText {
				flush := buf.feed(text)
				if sessionID != "" {
					flush = v.Restore(sessionID, flush)
				}
				part["text"] = flush
				continue
			}
			if fc, ok := part["functionCall"].(map[string]interface{}); ok && sessionID != "" {
				restored := redactJSON(fc, func(s string) string {
					return v.Restore(sessionID, s)
				})
				if m, ok := restored.(map[string]interface{}); ok {
					part["functionCall"] = m
				}
			}
		}

		if finishReason, _ := cand["finishReason"].(string); finishReason != "" {
			remainder := buf.drain()
			delete(buffers, idx)
			if remainder != "" {
				if sessionID != "" {
					remainder = v.Restore(sessionID, remainder)
				}
				appendGeminiTextRemainder(content, remainder)
			}
		}
	}
}

// appendGeminiTextRemainder attaches a drained buffer remainder to the
// candidate's existing text part if there is one in this chunk, or
// synthesizes one if the finishing chunk carried none of its own.
func appendGeminiTextRemainder(content map[string]interface{}, remainder string) {
	parts, _ := content["parts"].([]interface{})
	for _, p := range parts {
		part, ok := p.(map[string]interface{})
		if !ok {
			continue
		}
		if existing, ok := part["text"].(string); ok {
			part["text"] = existing + remainder
			return
		}
	}
	content["parts"] = append(parts, map[string]interface{}{"text": remainder})
}
