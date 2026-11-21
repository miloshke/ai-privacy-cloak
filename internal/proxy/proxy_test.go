package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"cloak/internal/detect"
	"cloak/internal/vault"
)

// This exercises the full request->redact->upstream->stream->restore path
// against a fake upstream that echoes back whatever (redacted) content it
// received, which is exactly how a model would echo a pasted secret back
// in its reply.
func TestServeHTTPRedactsRequestAndRestoresStreamedResponse(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var parsed map[string]interface{}
		if err := json.Unmarshal(body, &parsed); err != nil {
			t.Fatalf("upstream got invalid JSON: %v", err)
		}
		messages := parsed["messages"].([]interface{})
		first := messages[0].(map[string]interface{})
		content := first["content"].(string)

		if strings.Contains(content, "AKIA") {
			t.Fatalf("upstream received an unredacted AWS key: %q", content)
		}
		if !strings.Contains(content, "{{AWS_ACCESS_KEY_1}}") {
			t.Fatalf("expected a placeholder in redacted content, got %q", content)
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)

		fmt.Fprint(w, "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n")
		flusher.Flush()
		deltaPayload, _ := json.Marshal(map[string]interface{}{
			"type":  "content_block_delta",
			"index": 0,
			"delta": map[string]interface{}{"type": "text_delta", "text": content},
		})
		fmt.Fprintf(w, "event: content_block_delta\ndata: %s\n\n", deltaPayload)
		flusher.Flush()
		fmt.Fprint(w, "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n")
		flusher.Flush()
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("failed to parse upstream URL: %v", err)
	}
	handler := New(upstreamURL, AnthropicProvider{}, detect.New(), vault.New(time.Minute))

	reqBody := `{"model":"claude-x","messages":[{"role":"user","content":"deploy key AKIAABCDEFGHIJKLMNOP please"}],"stream":true}`
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(reqBody))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	respBody := rec.Body.String()
	if strings.Contains(respBody, "{{AWS_ACCESS_KEY_1}}") {
		t.Errorf("expected placeholder to be restored in response, got raw placeholder: %s", respBody)
	}
	if !strings.Contains(respBody, "AKIAABCDEFGHIJKLMNOP") {
		t.Errorf("expected original secret restored in response, got: %s", respBody)
	}
}

// Same end-to-end path as above, but the upstream splits the placeholder
// tag itself across two separate SSE deltas - the exact case
// placeholderBuffer exists to handle, now proven through the real HTTP
// handler rather than just the buffer in isolation.
func TestServeHTTPRestoresPlaceholderSplitAcrossStreamChunks(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var parsed map[string]interface{}
		_ = json.Unmarshal(body, &parsed)
		messages := parsed["messages"].([]interface{})
		first := messages[0].(map[string]interface{})
		content := first["content"].(string)

		splitAt := strings.Index(content, "{{AWS_ACCESS")
		if splitAt == -1 {
			t.Fatalf("expected a placeholder tag to split, got %q", content)
		}
		splitAt += len("{{AWS_ACCESS") // land the boundary mid-tag, not before it

		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)

		fmt.Fprint(w, "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n")
		flusher.Flush()

		for _, chunk := range []string{content[:splitAt], content[splitAt:]} {
			deltaPayload, _ := json.Marshal(map[string]interface{}{
				"type":  "content_block_delta",
				"index": 0,
				"delta": map[string]interface{}{"type": "text_delta", "text": chunk},
			})
			fmt.Fprintf(w, "event: content_block_delta\ndata: %s\n\n", deltaPayload)
			flusher.Flush()
		}
		fmt.Fprint(w, "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n")
		flusher.Flush()
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("failed to parse upstream URL: %v", err)
	}
	handler := New(upstreamURL, AnthropicProvider{}, detect.New(), vault.New(time.Minute))

	reqBody := `{"model":"claude-x","messages":[{"role":"user","content":"deploy key AKIAABCDEFGHIJKLMNOP please"}],"stream":true}`
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(reqBody))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	respBody := rec.Body.String()
	if strings.Contains(respBody, "{{AWS_ACCESS_KEY_1}}") || strings.Contains(respBody, "{{AWS_ACCESS") {
		t.Errorf("expected the split placeholder to be restored, got raw tag fragment in: %s", respBody)
	}
	if !strings.Contains(respBody, "AKIAABCDEFGHIJKLMNOP") {
		t.Errorf("expected original secret restored in response, got: %s", respBody)
	}
}

// The scenario that makes tool-call restoration more than a coverage gap:
// the agent reads a file containing a secret (redacted to a placeholder
// on the way in), then streams a tool call to write that file back out.
// If the placeholder in the streamed tool-call arguments isn't restored,
// the agent would write literal "{{...}}" text into the file instead of
// the real secret - this proves it gets restored, split across chunks
// exactly like the text case above.
func TestServeHTTPRestoresPlaceholderInStreamedToolCallArguments(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var parsed map[string]interface{}
		_ = json.Unmarshal(body, &parsed)
		messages := parsed["messages"].([]interface{})
		first := messages[0].(map[string]interface{})
		content := first["content"].(string)

		if strings.Contains(content, "AKIA") {
			t.Fatalf("upstream received an unredacted AWS key: %q", content)
		}

		// Simulate the model calling a write_file tool whose arguments
		// echo the (redacted) file content back, with the JSON arguments
		// streamed in pieces that split the placeholder tag mid-tag.
		args := `{"path":"deploy.env","content":"KEY=` + strings.TrimSpace(strings.SplitN(content, "key ", 2)[1])
		args = strings.TrimSuffix(args, " please") + `"}`
		splitAt := strings.Index(args, "{{AWS_ACCESS")
		if splitAt == -1 {
			t.Fatalf("expected a placeholder tag in tool-call arguments, got %q", args)
		}
		splitAt += len("{{AWS_ACCESS")

		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)

		fmt.Fprint(w, "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,"+
			"\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_1\",\"name\":\"write_file\",\"input\":{}}}\n\n")
		flusher.Flush()

		for _, chunk := range []string{args[:splitAt], args[splitAt:]} {
			deltaPayload, _ := json.Marshal(map[string]interface{}{
				"type":  "content_block_delta",
				"index": 0,
				"delta": map[string]interface{}{"type": "input_json_delta", "partial_json": chunk},
			})
			fmt.Fprintf(w, "event: content_block_delta\ndata: %s\n\n", deltaPayload)
			flusher.Flush()
		}
		fmt.Fprint(w, "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n")
		flusher.Flush()
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("failed to parse upstream URL: %v", err)
	}
	handler := New(upstreamURL, AnthropicProvider{}, detect.New(), vault.New(time.Minute))

	reqBody := `{"model":"claude-x","messages":[{"role":"user","content":"deploy key AKIAABCDEFGHIJKLMNOP please"}],"stream":true}`
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(reqBody))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	respBody := rec.Body.String()
	if strings.Contains(respBody, "{{AWS_ACCESS") {
		t.Errorf("expected the placeholder in tool-call arguments to be restored, got raw tag fragment in: %s", respBody)
	}
	if !strings.Contains(respBody, "AKIAABCDEFGHIJKLMNOP") {
		t.Errorf("expected original secret restored in tool-call arguments, got: %s", respBody)
	}
	if !strings.Contains(respBody, "input_json_delta") {
		t.Errorf("expected input_json_delta events to be forwarded, got: %s", respBody)
	}
}
