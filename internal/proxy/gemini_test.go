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

func TestGeminiDeriveSessionIDStableAcrossTurns(t *testing.T) {
	p := GeminiProvider{}
	turn1 := map[string]interface{}{
		"systemInstruction": map[string]interface{}{"parts": []interface{}{map[string]interface{}{"text": "you are helpful"}}},
		"contents": []interface{}{
			map[string]interface{}{"role": "user", "parts": []interface{}{map[string]interface{}{"text": "hello"}}},
		},
	}
	turn2 := map[string]interface{}{
		"systemInstruction": map[string]interface{}{"parts": []interface{}{map[string]interface{}{"text": "you are helpful"}}},
		"contents": []interface{}{
			map[string]interface{}{"role": "user", "parts": []interface{}{map[string]interface{}{"text": "hello"}}},
			map[string]interface{}{"role": "model", "parts": []interface{}{map[string]interface{}{"text": "hi there"}}},
			map[string]interface{}{"role": "user", "parts": []interface{}{map[string]interface{}{"text": "a second question"}}},
		},
	}

	id1 := p.DeriveSessionID(turn1)
	id2 := p.DeriveSessionID(turn2)
	if id1 != id2 {
		t.Errorf("expected the same session id across turns, got %q and %q", id1, id2)
	}

	other := map[string]interface{}{
		"systemInstruction": map[string]interface{}{"parts": []interface{}{map[string]interface{}{"text": "a different prompt"}}},
		"contents": []interface{}{
			map[string]interface{}{"role": "user", "parts": []interface{}{map[string]interface{}{"text": "hello"}}},
		},
	}
	if p.DeriveSessionID(other) == id1 {
		t.Error("expected a different conversation to hash to a different session id")
	}
}

func TestServeHTTPGeminiRestoresPlaceholderSplitAcrossStreamChunks(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var parsed map[string]interface{}
		_ = json.Unmarshal(body, &parsed)
		contents := parsed["contents"].([]interface{})
		last := contents[len(contents)-1].(map[string]interface{})
		parts := last["parts"].([]interface{})
		content := parts[0].(map[string]interface{})["text"].(string)

		splitAt := strings.Index(content, "{{AWS_ACCESS")
		if splitAt == -1 {
			t.Fatalf("expected a placeholder tag to split, got %q", content)
		}
		splitAt += len("{{AWS_ACCESS")

		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)

		chunks := []string{content[:splitAt], content[splitAt:]}
		for i, chunk := range chunks {
			cand := map[string]interface{}{
				"index":   0,
				"content": map[string]interface{}{"role": "model", "parts": []interface{}{map[string]interface{}{"text": chunk}}},
			}
			if i == len(chunks)-1 {
				cand["finishReason"] = "STOP"
			}
			payload, _ := json.Marshal(map[string]interface{}{"candidates": []interface{}{cand}})
			fmt.Fprintf(w, "data: %s\n\n", payload)
			flusher.Flush()
		}
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("failed to parse upstream URL: %v", err)
	}
	handler := New(upstreamURL, GeminiProvider{}, detect.New(), vault.New(time.Minute))

	reqBody := `{"contents":[{"role":"user","parts":[{"text":"deploy key AKIAABCDEFGHIJKLMNOP please"}]}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1beta/models/gemini-x:streamGenerateContent", strings.NewReader(reqBody))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	respBody := rec.Body.String()
	if strings.Contains(respBody, "{{AWS_ACCESS") {
		t.Errorf("expected the split placeholder to be restored, got raw tag fragment in: %s", respBody)
	}
	if !strings.Contains(respBody, "AKIAABCDEFGHIJKLMNOP") {
		t.Errorf("expected original secret restored in response, got: %s", respBody)
	}
}

// functionCall parts arrive whole rather than streamed incrementally, so
// this proves the one-pass restore via the shared redactJSON walker -
// same correctness concern as the other providers' tool-call tests: a
// redacted secret echoed back inside a tool call's arguments must come
// back as the real value, not the literal placeholder.
func TestServeHTTPGeminiRestoresPlaceholderInFunctionCallArgs(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var parsed map[string]interface{}
		_ = json.Unmarshal(body, &parsed)
		contents := parsed["contents"].([]interface{})
		last := contents[len(contents)-1].(map[string]interface{})
		parts := last["parts"].([]interface{})
		content := parts[0].(map[string]interface{})["text"].(string)

		if strings.Contains(content, "AKIA") {
			t.Fatalf("upstream received an unredacted AWS key: %q", content)
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)

		cand := map[string]interface{}{
			"index": 0,
			"content": map[string]interface{}{
				"role": "model",
				"parts": []interface{}{
					map[string]interface{}{
						"functionCall": map[string]interface{}{
							"name": "write_file",
							"args": map[string]interface{}{
								"path":    "deploy.env",
								"content": "KEY=" + content,
							},
						},
					},
				},
			},
			"finishReason": "STOP",
		}
		payload, _ := json.Marshal(map[string]interface{}{"candidates": []interface{}{cand}})
		fmt.Fprintf(w, "data: %s\n\n", payload)
		flusher.Flush()
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("failed to parse upstream URL: %v", err)
	}
	handler := New(upstreamURL, GeminiProvider{}, detect.New(), vault.New(time.Minute))

	reqBody := `{"contents":[{"role":"user","parts":[{"text":"AKIAABCDEFGHIJKLMNOP"}]}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1beta/models/gemini-x:streamGenerateContent", strings.NewReader(reqBody))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	respBody := rec.Body.String()
	if strings.Contains(respBody, "{{AWS_ACCESS") {
		t.Errorf("expected the placeholder in functionCall args to be restored, got raw tag fragment in: %s", respBody)
	}
	if !strings.Contains(respBody, "AKIAABCDEFGHIJKLMNOP") {
		t.Errorf("expected original secret restored in functionCall args, got: %s", respBody)
	}
	if !strings.Contains(respBody, "write_file") {
		t.Errorf("expected the function call name to still be forwarded, got: %s", respBody)
	}
}
