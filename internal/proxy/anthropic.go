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

// AnthropicProvider implements Provider for the Anthropic Messages API.
type AnthropicProvider struct{}

func (AnthropicProvider) Name() string { return "anthropic" }

// DeriveSessionID hashes the system prompt and first message, both of
// which agent CLIs resend unchanged on every turn of a conversation, into
// a stable key for the vault.
func (AnthropicProvider) DeriveSessionID(parsed map[string]interface{}) string {
	h := sha256.New()
	if system, ok := parsed["system"]; ok {
		b, _ := json.Marshal(system)
		h.Write(b)
	}
	if messages, ok := parsed["messages"].([]interface{}); ok && len(messages) > 0 {
		b, _ := json.Marshal(messages[0])
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// anthropicBlock tracks one content block's streaming state. kind comes
// from content_block_start's content_block.type ("text" or "tool_use")
// and never changes mid-block, so it's read once and reused to pick the
// right delta shape (text_delta vs input_json_delta) for every delta and
// for the final remainder flush.
type anthropicBlock struct {
	buf  *placeholderBuffer
	kind string
}

// StreamRestore relays an Anthropic SSE stream to the client, restoring
// placeholders in each content block as it streams rather than waiting
// for the block to close - for both plain text (text_delta) and streamed
// tool-call arguments (input_json_delta). The latter matters more than it
// looks: a coding agent routinely echoes previously-redacted file content
// back through a tool call (e.g. "edit this file and write it back"), so
// skipping restoration there would leave literal "{{...}}" placeholder
// text in a file the agent writes to disk - a correctness bug, not just a
// coverage gap.
//
// The hard part is unchanged from the text-only version: a placeholder
// like "{{EMAIL_1}}" can straddle an arbitrary chunk boundary, so
// forwarding deltas verbatim as they arrive could split one mid-tag and
// leave it unrestored. placeholderBuffer (stream.go) holds back only the
// minimal suffix that could still be the start of an unterminated
// "{{...}}" tag, and flushes everything else immediately.
func (AnthropicProvider) StreamRestore(w http.ResponseWriter, body io.Reader, v *vault.Vault, sessionID string) {
	flusher, _ := w.(http.Flusher)
	scanner := newSSEScanner(body)

	blocks := map[int]*anthropicBlock{}
	var lines []string

	flushBlock := func() {
		if len(lines) == 0 {
			return
		}
		handleAnthropicSSEBlock(w, lines, blocks, v, sessionID)
		lines = lines[:0]
		if flusher != nil {
			flusher.Flush()
		}
	}

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			flushBlock()
			continue
		}
		lines = append(lines, line)
	}
	flushBlock()
	logScannerError("anthropic", scanner.Err())
}

func handleAnthropicSSEBlock(w http.ResponseWriter, lines []string, blocks map[int]*anthropicBlock, v *vault.Vault, sessionID string) {
	var dataLine string
	for _, l := range lines {
		if strings.HasPrefix(l, "data: ") {
			dataLine = strings.TrimPrefix(l, "data: ")
		}
	}

	var evt map[string]interface{}
	if dataLine == "" || json.Unmarshal([]byte(dataLine), &evt) != nil {
		writeRawSSELines(w, lines)
		return
	}

	switch evt["type"] {
	case "content_block_start":
		if idx, ok := sseBlockIndex(evt); ok {
			kind := "text"
			if cb, ok := evt["content_block"].(map[string]interface{}); ok {
				if t, ok := cb["type"].(string); ok {
					kind = t
				}
			}
			blocks[idx] = &anthropicBlock{buf: &placeholderBuffer{}, kind: kind}
		}
		writeRawSSELines(w, lines)

	case "content_block_delta":
		idx, hasIdx := sseBlockIndex(evt)
		block, hasBlock := blocks[idx]
		if !hasIdx || !hasBlock {
			writeRawSSELines(w, lines)
			return
		}
		delta, _ := evt["delta"].(map[string]interface{})

		var raw string
		var isMatch bool
		if block.kind == "tool_use" {
			raw, isMatch = delta["partial_json"].(string)
		} else {
			raw, isMatch = delta["text"].(string)
		}
		if !isMatch {
			// Unexpected delta shape for this block's kind - pass through
			// unmodified rather than risk mangling something we don't
			// understand.
			writeRawSSELines(w, lines)
			return
		}

		flush := block.buf.feed(raw)
		if sessionID != "" {
			flush = v.Restore(sessionID, flush)
		}
		if flush != "" {
			writeAnthropicDeltaEvent(w, idx, block.kind, flush)
		}
		// else: the whole chunk might be the start of a placeholder tag -
		// held back in buf until a closing "}}" arrives or the block ends.

	case "content_block_stop":
		idx, hasIdx := sseBlockIndex(evt)
		if hasIdx {
			if block, ok := blocks[idx]; ok {
				remainder := block.buf.drain()
				if sessionID != "" {
					remainder = v.Restore(sessionID, remainder)
				}
				delete(blocks, idx)
				if remainder != "" {
					writeAnthropicDeltaEvent(w, idx, block.kind, remainder)
				}
			}
		}
		writeRawSSELines(w, lines)

	default:
		writeRawSSELines(w, lines)
	}
}

func sseBlockIndex(evt map[string]interface{}) (int, bool) {
	f, ok := evt["index"].(float64)
	if !ok {
		return 0, false
	}
	return int(f), true
}

func writeRawSSELines(w http.ResponseWriter, lines []string) {
	for _, l := range lines {
		fmt.Fprintf(w, "%s\n", l)
	}
	fmt.Fprint(w, "\n")
}

// writeAnthropicDeltaEvent emits a content_block_delta for either a text
// block (text_delta) or a tool_use block (input_json_delta) depending on
// blockKind, which is the content block's own content_block.type.
func writeAnthropicDeltaEvent(w http.ResponseWriter, index int, blockKind, value string) {
	deltaType, field := "text_delta", "text"
	if blockKind == "tool_use" {
		deltaType, field = "input_json_delta", "partial_json"
	}
	evt := map[string]interface{}{
		"type":  "content_block_delta",
		"index": index,
		"delta": map[string]interface{}{"type": deltaType, field: value},
	}
	payload, _ := json.Marshal(evt)
	fmt.Fprintf(w, "event: content_block_delta\ndata: %s\n\n", payload)
}
