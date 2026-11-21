package proxy

import (
	"encoding/json"
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

func TestToolUseIDSurvivesRedactionUnmangled(t *testing.T) {
	var receivedBody map[string]interface{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &receivedBody)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("failed to parse upstream URL: %v", err)
	}
	handler := New(u, AnthropicProvider{}, detect.New(), vault.New(time.Minute))

	// A realistic multi-turn conversation that echoes back a prior
	// assistant tool_use block - exactly the shape Claude Code resends.
	reqBody := `{
		"model": "claude-3-5-sonnet-20241022",
		"messages": [
			{"role": "user", "content": "read the config file"},
			{"role": "assistant", "content": [
				{"type": "tool_use", "id": "msg_01XFDUDYJgAACzvnptvVoYEL", "name": "read_file", "input": {"path": "config.env"}}
			]},
			{"role": "user", "content": [
				{"type": "tool_result", "tool_use_id": "msg_01XFDUDYJgAACzvnptvVoYEL", "content": "AWS_KEY=AKIAABCDEFGHIJKLMNOP"}
			]}
		]
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(reqBody))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	messages := receivedBody["messages"].([]interface{})
	assistantMsg := messages[1].(map[string]interface{})
	toolUseBlock := assistantMsg["content"].([]interface{})[0].(map[string]interface{})
	id := toolUseBlock["id"].(string)

	if id != "msg_01XFDUDYJgAACzvnptvVoYEL" {
		t.Errorf("expected tool_use.id to survive untouched, got %q", id)
	}
	if strings.Contains(id, "{{") {
		t.Errorf("tool_use.id got mangled into a placeholder - this is exactly what breaks Anthropic's ^[a-zA-Z0-9_-]+$ validation: %q", id)
	}

	userMsg := messages[2].(map[string]interface{})
	toolResultBlock := userMsg["content"].([]interface{})[0].(map[string]interface{})
	toolUseID := toolResultBlock["tool_use_id"].(string)
	if toolUseID != "msg_01XFDUDYJgAACzvnptvVoYEL" {
		t.Errorf("expected tool_result.tool_use_id to survive untouched, got %q", toolUseID)
	}

	// The actual secret, which is real user content (not a structural
	// field), must still get redacted.
	resultContent := toolResultBlock["content"].(string)
	if strings.Contains(resultContent, "AKIA") {
		t.Errorf("expected the AWS key inside tool_result content to still be redacted, got %q", resultContent)
	}
}

// Same bug, OpenAI's field naming: tool_calls[].id rather than
// Anthropic's top-level content-block id, and a "tool" role message's
// own tool_call_id back-reference rather than tool_use_id.
func TestOpenAIToolCallIDSurvivesRedactionUnmangled(t *testing.T) {
	var receivedBody map[string]interface{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &receivedBody)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("failed to parse upstream URL: %v", err)
	}
	handler := New(u, OpenAIProvider{}, detect.New(), vault.New(time.Minute))

	reqBody := `{
		"model": "gpt-4",
		"messages": [
			{"role": "user", "content": "read the config file"},
			{"role": "assistant", "tool_calls": [
				{"id": "call_FthC9qRpvrtC2QS8Kv82rI5Q", "type": "function", "function": {"name": "read_file", "arguments": "{\"path\":\"config.env\"}"}}
			]},
			{"role": "tool", "tool_call_id": "call_FthC9qRpvrtC2QS8Kv82rI5Q", "content": "AWS_KEY=AKIAABCDEFGHIJKLMNOP"}
		]
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(reqBody))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	messages := receivedBody["messages"].([]interface{})
	assistantMsg := messages[1].(map[string]interface{})
	toolCall := assistantMsg["tool_calls"].([]interface{})[0].(map[string]interface{})
	id := toolCall["id"].(string)
	if id != "call_FthC9qRpvrtC2QS8Kv82rI5Q" {
		t.Errorf("expected tool_calls[].id to survive untouched, got %q", id)
	}

	toolMsg := messages[2].(map[string]interface{})
	toolCallID := toolMsg["tool_call_id"].(string)
	if toolCallID != "call_FthC9qRpvrtC2QS8Kv82rI5Q" {
		t.Errorf("expected tool_call_id to survive untouched, got %q", toolCallID)
	}

	resultContent := toolMsg["content"].(string)
	if strings.Contains(resultContent, "AKIA") {
		t.Errorf("expected the AWS key inside the tool message content to still be redacted, got %q", resultContent)
	}
}

// The extended-thinking signature case: a cryptographic signature over
// the thinking content, not text anyone wrote. Same bug class as the
// tool_use.id case above - this one is short enough that bounding
// HIGH_ENTROPY_SECRET's length wouldn't exclude it on its own, so it
// needs its own structuralKeys entry.
func TestThinkingSignatureSurvivesRedactionUnmangled(t *testing.T) {
	var receivedBody map[string]interface{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &receivedBody)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("failed to parse upstream URL: %v", err)
	}
	handler := New(u, AnthropicProvider{}, detect.New(), vault.New(time.Minute))

	sig := "EqoBCkgIARABGAIiQEb3n9F2k8xQp4zR7mL1wNcVjH5tB6yU9aP0sD2eK8iO3uWg7fH1vN6xT4qR9mP2sL5kJ8dC3bA0zY6wE1nM4oI7hG9jFkDl0="
	reqBody := `{
		"model": "claude-3-5-sonnet-20241022",
		"messages": [
			{"role": "user", "content": "think about this"},
			{"role": "assistant", "content": [
				{"type": "thinking", "thinking": "reasoning here", "signature": "` + sig + `"}
			]}
		]
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(reqBody))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	messages := receivedBody["messages"].([]interface{})
	assistantMsg := messages[1].(map[string]interface{})
	thinkingBlock := assistantMsg["content"].([]interface{})[0].(map[string]interface{})
	got := thinkingBlock["signature"].(string)

	if got != sig {
		t.Errorf("expected the thinking signature to survive untouched, got %q", got)
	}
}
