package proxy

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"cloak/internal/detect"
	"cloak/internal/vault"
)

// Before logScannerError existed, bufio.Scanner failing on an oversized
// line (base64 image data, a large file written via a tool call, ...)
// just made Scan return false - the stream would truncate with no trace
// of why anywhere. This proves it's at least surfaced now, and that it
// doesn't crash or hang the handler.
func TestOversizedSSELineIsLoggedNotSwallowedSilently(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)

		fmt.Fprint(w, "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n")
		flusher.Flush()

		// One SSE line bigger than maxSSELineSize.
		oversized := strings.Repeat("x", maxSSELineSize+1024)
		fmt.Fprintf(w, "data: %s\n\n", oversized)
		flusher.Flush()
	}))
	defer upstream.Close()

	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("failed to parse upstream URL: %v", err)
	}
	handler := New(u, AnthropicProvider{}, detect.New(), vault.New(time.Minute))

	var logBuf bytes.Buffer
	origOutput := log.Writer()
	log.SetOutput(&logBuf)
	defer log.SetOutput(origOutput)

	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		handler.ServeHTTP(rec, req)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not return - an oversized line should end the stream, not hang it")
	}

	if !strings.Contains(logBuf.String(), "anthropic stream ended early") {
		t.Errorf("expected the oversized-line error to be logged, got log output: %q", logBuf.String())
	}
}
