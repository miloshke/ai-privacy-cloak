package proxy

import (
	"context"
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

func TestCombineSessionIDDiffersByConnectionNotJustContent(t *testing.T) {
	const content = "same system prompt + first message"

	if combineSessionID(1, content) == combineSessionID(2, content) {
		t.Fatal("combineSessionID must differ across connections even with identical content")
	}
	if combineSessionID(1, content) != combineSessionID(1, content) {
		t.Fatal("combineSessionID must be stable for the same connection and content")
	}
}

// withConnID simulates what ConnContext (connid.go) attaches to a real
// request's context for a given underlying TCP connection, without
// needing an actual net.Conn - the production code path is exercised
// separately by the fact that http.Server.ConnContext is wired to
// ConnContext in cmd/cloak.
func withConnID(req *http.Request, id uint64) *http.Request {
	return req.WithContext(context.WithValue(req.Context(), connIDKey{}, id))
}

// TestServeHTTPDoesNotCollideAcrossConnectionsWithIdenticalContent
// reproduces the session-ID collision this fix closes: two unrelated
// conversations (distinct TCP connections) whose opening content is
// byte-identical used to hash to the same vault bucket. Session A
// redacts a real secret into a placeholder; session B's upstream then
// echoes that exact placeholder tag back verbatim (simulating the
// dangerous case where a colliding session's response happens to
// reproduce another session's tag). Without mixing connection identity
// into the session ID, B's restore step would find A's secret in the
// shared bucket and leak it into B's response.
func TestServeHTTPDoesNotCollideAcrossConnectionsWithIdenticalContent(t *testing.T) {
	const secret = "AKIAABCDEFGHIJKLMNOP"
	const leakedPlaceholder = "{{AWS_ACCESS_KEY_1}}"

	sharedVault := vault.New(time.Minute)

	// Both sessions share the exact same first message - the content
	// DeriveSessionID hashes - so the content-derived portion of the
	// session id collides, same as the real "two terminal tabs with the
	// same opening text" scenario. The secret only ever appears in A's
	// *second* message, so B's own request never causes B's vault bucket
	// to independently learn the same placeholder - any restoration B
	// performs for it can only come from a shared bucket with A.
	const firstMessage = "fix the bug please"

	// Session A: upstream echoes back the second message, which contains
	// the real secret and gets redacted/restored normally.
	upstreamA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var parsed map[string]interface{}
		json.Unmarshal(body, &parsed)
		second := parsed["messages"].([]interface{})[1].(map[string]interface{})["content"].(string)
		writeTextSSE(w, second)
	}))
	defer upstreamA.Close()
	upstreamAURL, _ := url.Parse(upstreamA.URL)
	handlerA := New(upstreamAURL, AnthropicProvider{}, detect.New(), sharedVault)

	reqBodyA := fmt.Sprintf(`{"model":"claude-x","messages":[{"role":"user","content":%q},{"role":"user","content":"deploy key %s please"}],"stream":true}`, firstMessage, secret)
	reqA := withConnID(httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(reqBodyA)), 1)
	recA := httptest.NewRecorder()
	handlerA.ServeHTTP(recA, reqA)

	if !strings.Contains(recA.Body.String(), secret) {
		t.Fatalf("session A should restore its own secret, got: %s", recA.Body.String())
	}

	// Session B: a different connection with the same first message as A
	// (so the content-derived id matches), but no secret anywhere in its
	// own request. Its upstream returns A's placeholder tag verbatim, as
	// if B's model output happened to reproduce it.
	upstreamB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.ReadAll(r.Body)
		writeTextSSE(w, "here is a tag that looks like a secret: "+leakedPlaceholder)
	}))
	defer upstreamB.Close()
	upstreamBURL, _ := url.Parse(upstreamB.URL)
	handlerB := New(upstreamBURL, AnthropicProvider{}, detect.New(), sharedVault)

	reqBodyB := fmt.Sprintf(`{"model":"claude-x","messages":[{"role":"user","content":%q},{"role":"user","content":"anything else, no secret here"}],"stream":true}`, firstMessage)
	reqB := withConnID(httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(reqBodyB)), 2)
	recB := httptest.NewRecorder()
	handlerB.ServeHTTP(recB, reqB)

	if strings.Contains(recB.Body.String(), secret) {
		t.Fatalf("session B must never see session A's secret via a shared vault bucket, got: %s", recB.Body.String())
	}
	if !strings.Contains(recB.Body.String(), leakedPlaceholder) {
		t.Fatalf("session B's unmatched placeholder should pass through untouched, got: %s", recB.Body.String())
	}
}

func writeTextSSE(w http.ResponseWriter, text string) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	flusher := w.(http.Flusher)

	fmt.Fprint(w, "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n")
	flusher.Flush()
	deltaPayload, _ := json.Marshal(map[string]interface{}{
		"type":  "content_block_delta",
		"index": 0,
		"delta": map[string]interface{}{"type": "text_delta", "text": text},
	})
	fmt.Fprintf(w, "event: content_block_delta\ndata: %s\n\n", deltaPayload)
	flusher.Flush()
	fmt.Fprint(w, "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n")
	flusher.Flush()
}
