package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"cloak/internal/detect"
	"cloak/internal/vault"
)

// Redaction needs the whole body parsed as JSON, unlike servePassthrough,
// which streams bytes through without ever buffering them - so without a
// cap, an agent pasting a very large file (exactly what this tool exists
// to scan) could balloon memory with no limit at all.
func TestOversizedRequestBodyIsRejectedNotBuffered(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("expected the oversized request to be rejected before ever reaching upstream")
	}))
	defer upstream.Close()

	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("failed to parse upstream URL: %v", err)
	}
	handler := New(u, AnthropicProvider{}, detect.New(), vault.New(time.Minute))

	oversized := strings.Repeat("a", maxRedactRequestBody+1024)
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(oversized))
	req.ContentLength = int64(len(oversized))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 413, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestRequestBodyUnderTheLimitStillWorks(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("failed to parse upstream URL: %v", err)
	}
	handler := New(u, AnthropicProvider{}, detect.New(), vault.New(time.Minute))

	body := `{"model":"x","messages":[{"role":"user","content":"hello"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}
