package proxy

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"cloak/internal/detect"
	"cloak/internal/vault"
)

// Forwarding a client's own Accept-Encoding header (many SDKs set one by
// default) disables Go's automatic "request gzip, transparently
// decompress the response" behavior in net/http.Transport - it only
// kicks in when the outgoing request has no Accept-Encoding of its own.
// Without stripping it, an upstream that decides to compress a response
// would hand us raw gzip bytes that json.Unmarshal/the SSE scanner/
// vault.Restore would all silently fail to parse: redaction and
// restoration would just never happen, with no error raised anywhere.
func gzipUpstream(t *testing.T, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Transport itself adds "Accept-Encoding: gzip" once the
		// client's own header is stripped - that's the mechanism that
		// lets it transparently decompress the response for us, so
		// seeing exactly "gzip" here (not the client's original
		// "gzip, deflate, br") is the expected, correct behavior.
		if enc := r.Header.Get("Accept-Encoding"); enc != "gzip" {
			t.Errorf(`expected Transport to request "gzip" itself, got %q`, enc)
		}
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		gz.Write([]byte(body))
		gz.Close()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		w.Write(buf.Bytes())
	}))
}

func TestServeHTTPHandlesGzipCompressedUpstreamResponse(t *testing.T) {
	upstream := gzipUpstream(t, `{"ok":true}`)
	defer upstream.Close()

	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("failed to parse upstream URL: %v", err)
	}
	handler := New(u, AnthropicProvider{}, detect.New(), vault.New(time.Minute))

	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(`{}`))
	req.Header.Set("Accept-Encoding", "gzip, deflate, br") // what a real SDK often sends
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Body.String() != `{"ok":true}` {
		t.Errorf("expected transparently decompressed JSON, got %q", rec.Body.String())
	}
	if enc := rec.Header().Get("Content-Encoding"); enc != "" {
		t.Errorf("expected no Content-Encoding header on an already-decompressed body, got %q", enc)
	}
}

// Same concern in passthrough (disabled) mode: servePassthrough shares
// requestStripHeaders, so it should get the same protection automatically.
func TestServePassthroughHandlesGzipCompressedUpstreamResponse(t *testing.T) {
	upstream := gzipUpstream(t, `{"ok":true}`)
	defer upstream.Close()

	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("failed to parse upstream URL: %v", err)
	}
	handler := New(u, AnthropicProvider{}, detect.New(), vault.New(time.Minute))
	postControl(t, handler, "disable")

	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(`{}`))
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Body.String() != `{"ok":true}` {
		t.Errorf("expected transparently decompressed JSON while disabled, got %q", rec.Body.String())
	}
}
