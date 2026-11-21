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

func TestOpenAIDeriveSessionIDStableAcrossTurns(t *testing.T) {
	p := OpenAIProvider{}
	turn1 := map[string]interface{}{
		"messages": []interface{}{
			map[string]interface{}{"role": "system", "content": "you are a helpful assistant"},
			map[string]interface{}{"role": "user", "content": "hello"},
		},
	}
	turn2 := map[string]interface{}{
		"messages": []interface{}{
			map[string]interface{}{"role": "system", "content": "you are a helpful assistant"},
			map[string]interface{}{"role": "user", "content": "hello"},
			map[string]interface{}{"role": "assistant", "content": "hi there"},
			map[string]interface{}{"role": "user", "content": "a second question"},
		},
	}

	id1 := p.DeriveSessionID(turn1)
	id2 := p.DeriveSessionID(turn2)
	if id1 != id2 {
		t.Errorf("expected the same session id across turns of one conversation, got %q and %q", id1, id2)
	}

	other := map[string]interface{}{
		"messages": []interface{}{
			map[string]interface{}{"role": "system", "content": "a totally different system prompt"},
			map[string]interface{}{"role": "user", "content": "hello"},
		},
	}
	if p.DeriveSessionID(other) == id1 {
		t.Error("expected a different conversation to hash to a different session id")
	}
}

// Full request->redact->upstream->stream->restore path against a fake
// OpenAI-shaped upstream, with the placeholder split across two separate
// SSE chunks - the same boundary case covered for Anthropic, now proven
// for OpenAI's flatter choices[].delta.content streaming shape.
func TestServeHTTPOpenAIRestoresPlaceholderSplitAcrossStreamChunks(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var parsed map[string]interface{}
		_ = json.Unmarshal(body, &parsed)
		messages := parsed["messages"].([]interface{})
		last := messages[len(messages)-1].(map[string]interface{})
		content := last["content"].(string)

		splitAt := strings.Index(content, "{{AWS_ACCESS")
		if splitAt == -1 {
			t.Fatalf("expected a placeholder tag to split, got %q", content)
		}
		splitAt += len("{{AWS_ACCESS")

		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)

		for _, chunk := range []string{content[:splitAt], content[splitAt:]} {
			payload, _ := json.Marshal(map[string]interface{}{
				"choices": []interface{}{
					map[string]interface{}{"index": 0, "delta": map[string]interface{}{"content": chunk}, "finish_reason": nil},
				},
			})
			fmt.Fprintf(w, "data: %s\n\n", payload)
			flusher.Flush()
		}
		finalPayload, _ := json.Marshal(map[string]interface{}{
			"choices": []interface{}{
				map[string]interface{}{"index": 0, "delta": map[string]interface{}{}, "finish_reason": "stop"},
			},
		})
		fmt.Fprintf(w, "data: %s\n\n", finalPayload)
		flusher.Flush()
		fmt.Fprint(w, "data: [DONE]\n\n")
		flusher.Flush()
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("failed to parse upstream URL: %v", err)
	}
	handler := New(upstreamURL, OpenAIProvider{}, detect.New(), vault.New(time.Minute))

	reqBody := `{"model":"gpt-x","messages":[{"role":"user","content":"deploy key AKIAABCDEFGHIJKLMNOP please"}],"stream":true}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(reqBody))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	respBody := rec.Body.String()
	if strings.Contains(respBody, "{{AWS_ACCESS_KEY_1}}") || strings.Contains(respBody, "{{AWS_ACCESS") {
		t.Errorf("expected the split placeholder to be restored, got raw tag fragment in: %s", respBody)
	}
	if !strings.Contains(respBody, "AKIAABCDEFGHIJKLMNOP") {
		t.Errorf("expected original secret restored in response, got: %s", respBody)
	}
	if !strings.Contains(respBody, "[DONE]") {
		t.Errorf("expected the [DONE] sentinel to be forwarded, got: %s", respBody)
	}
}

// Same correctness concern as the Anthropic tool_use test: a redacted
// secret echoed back inside a streamed OpenAI tool call's
// function.arguments must come back restored, not as a literal
// placeholder, split across chunks mid-tag and spread across two
// separate tool_calls deltas (as a real streamed function call would be).
func TestServeHTTPOpenAIRestoresPlaceholderInStreamedToolCallArguments(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var parsed map[string]interface{}
		_ = json.Unmarshal(body, &parsed)
		messages := parsed["messages"].([]interface{})
		last := messages[len(messages)-1].(map[string]interface{})
		content := last["content"].(string)

		if strings.Contains(content, "AKIA") {
			t.Fatalf("upstream received an unredacted AWS key: %q", content)
		}

		args := `{"path":"deploy.env","content":"KEY=` + content + `"}`
		splitAt := strings.Index(args, "{{AWS_ACCESS")
		if splitAt == -1 {
			t.Fatalf("expected a placeholder tag in tool-call arguments, got %q", args)
		}
		splitAt += len("{{AWS_ACCESS")

		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)

		for i, chunk := range []string{args[:splitAt], args[splitAt:]} {
			toolCall := map[string]interface{}{
				"index":    0,
				"function": map[string]interface{}{"arguments": chunk},
			}
			if i == 0 {
				toolCall["id"] = "call_1"
				toolCall["type"] = "function"
				toolCall["function"].(map[string]interface{})["name"] = "write_file"
			}
			payload, _ := json.Marshal(map[string]interface{}{
				"choices": []interface{}{
					map[string]interface{}{
						"index":         0,
						"delta":         map[string]interface{}{"tool_calls": []interface{}{toolCall}},
						"finish_reason": nil,
					},
				},
			})
			fmt.Fprintf(w, "data: %s\n\n", payload)
			flusher.Flush()
		}
		finalPayload, _ := json.Marshal(map[string]interface{}{
			"choices": []interface{}{
				map[string]interface{}{"index": 0, "delta": map[string]interface{}{}, "finish_reason": "tool_calls"},
			},
		})
		fmt.Fprintf(w, "data: %s\n\n", finalPayload)
		flusher.Flush()
		fmt.Fprint(w, "data: [DONE]\n\n")
		flusher.Flush()
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("failed to parse upstream URL: %v", err)
	}
	handler := New(upstreamURL, OpenAIProvider{}, detect.New(), vault.New(time.Minute))

	reqBody := `{"model":"gpt-x","messages":[{"role":"user","content":"AKIAABCDEFGHIJKLMNOP"}],"stream":true}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(reqBody))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	respBody := rec.Body.String()
	if strings.Contains(respBody, "{{AWS_ACCESS") {
		t.Errorf("expected the placeholder in tool-call arguments to be restored, got raw tag fragment in: %s", respBody)
	}
	if !strings.Contains(respBody, "AKIAABCDEFGHIJKLMNOP") {
		t.Errorf("expected original secret restored in tool-call arguments, got: %s", respBody)
	}
	if !strings.Contains(respBody, "write_file") {
		t.Errorf("expected the tool call's name/id to still be forwarded, got: %s", respBody)
	}
}
