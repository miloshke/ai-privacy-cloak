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

func newTestHandler(t *testing.T, upstreamURL string) *Handler {
	t.Helper()
	u, err := url.Parse(upstreamURL)
	if err != nil {
		t.Fatalf("failed to parse upstream URL: %v", err)
	}
	return New(u, AnthropicProvider{}, detect.New(), vault.New(time.Minute))
}

func TestControlStatusDefaultsToEnabled(t *testing.T) {
	handler := newTestHandler(t, "http://unused.invalid")

	req := httptest.NewRequest(http.MethodGet, "/__cloak__/status", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var status struct {
		Enabled  bool   `json:"enabled"`
		Provider string `json:"provider"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil {
		t.Fatalf("failed to parse status response %q: %v", rec.Body.String(), err)
	}
	if !status.Enabled {
		t.Error("expected protection to default to enabled")
	}
	if status.Provider != "anthropic" {
		t.Errorf("expected provider %q, got %q", "anthropic", status.Provider)
	}
}

func TestControlMutatingActionsRejectGET(t *testing.T) {
	handler := newTestHandler(t, "http://unused.invalid")

	for _, action := range []string{"enable", "disable", "toggle"} {
		req := httptest.NewRequest(http.MethodGet, "/__cloak__/"+action, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET /__cloak__/%s: expected 405, got %d", action, rec.Code)
		}
	}
}

func TestControlToggleFlipsState(t *testing.T) {
	handler := newTestHandler(t, "http://unused.invalid")

	status := postControl(t, handler, "disable")
	if status["enabled"].(bool) {
		t.Fatal("expected disabled after POST disable")
	}

	status = postControl(t, handler, "toggle")
	if !status["enabled"].(bool) {
		t.Fatal("expected enabled after toggling from disabled")
	}

	status = postControl(t, handler, "toggle")
	if status["enabled"].(bool) {
		t.Fatal("expected disabled after toggling from enabled")
	}
}

func postControl(t *testing.T, handler *Handler, action string) map[string]interface{} {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/__cloak__/"+action, nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var status map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil {
		t.Fatalf("failed to parse status response %q: %v", rec.Body.String(), err)
	}
	return status
}

// When disabled, a secret must pass through completely unredacted - not
// "redaction ran and found nothing to do", but "nothing touched it".
func TestDisabledHandlerDoesNotRedact(t *testing.T) {
	var receivedBody string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	handler := newTestHandler(t, upstream.URL)
	postControl(t, handler, "disable")

	reqBody := `{"model":"claude-x","messages":[{"role":"user","content":"deploy key AKIAABCDEFGHIJKLMNOP please"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(reqBody))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if receivedBody != reqBody {
		t.Errorf("expected the upstream to receive the request byte-for-byte unmodified while disabled, got %q", receivedBody)
	}
	if rec.Body.String() != `{"ok":true}` {
		t.Errorf("expected the response to pass through unmodified, got %q", rec.Body.String())
	}
}

// Re-enabling must restore normal redaction behavior - the toggle isn't
// a one-way trip.
func TestReenablingHandlerRedactsAgain(t *testing.T) {
	var receivedBody string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	handler := newTestHandler(t, upstream.URL)
	postControl(t, handler, "disable")
	postControl(t, handler, "enable")

	reqBody := `{"model":"claude-x","messages":[{"role":"user","content":"deploy key AKIAABCDEFGHIJKLMNOP please"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(reqBody))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if strings.Contains(receivedBody, "AKIA") {
		t.Errorf("expected the secret to be redacted again after re-enabling, got %q", receivedBody)
	}
}
