// Package proxy implements a reverse proxy for AI model provider APIs
// (Anthropic, OpenAI, ...) that redacts secrets/PII from outgoing requests
// and restores them in the response, so the model provider never sees
// plaintext credentials while the caller sees clean, original text.
// Wire-protocol differences between providers live behind the Provider
// interface (provider.go); everything else here is shared.
package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"

	"cloak/internal/detect"
	"cloak/internal/vault"
)

// controlPathPrefix routes requests to the runtime control API instead of
// the upstream provider. "/v1/..." (every real provider API path) can
// never collide with it, so this is safe to check unconditionally.
const controlPathPrefix = "/__cloak__/"

// maxRedactRequestBody bounds how much of a request body the redaction
// path will buffer into memory. Redaction fundamentally needs the whole
// body parsed as JSON - unlike servePassthrough, which streams bytes
// through without ever buffering the whole thing - so an agent pasting a
// very large file (exactly the kind of content this tool exists to
// scan) could otherwise balloon memory with no limit at all. 64MB is
// generous for real request bodies while still bounding the worst case.
const maxRedactRequestBody = 64 * 1024 * 1024

// requestStripHeaders are excluded when building the outgoing request:
// transport metadata (so the provider sees this machine's fingerprint as
// little as possible), headers that must be recomputed for a rewritten
// body rather than forwarded verbatim, and Accept-Encoding - forwarding
// a client's own Accept-Encoding disables Go's net/http automatic
// gzip-request-and-transparently-decompress behavior (it only kicks in
// when the request has no Accept-Encoding of its own), so a response the
// upstream decides to compress would arrive as raw gzip bytes that
// json.Unmarshal/the SSE scanner/vault.Restore would all silently fail to
// parse - redaction and restoration would just never happen, with no
// error. Stripping it lets Transport negotiate and decompress for us.
var requestStripHeaders = []string{"User-Agent", "X-Forwarded-For", "X-Real-Ip", "Via", "Content-Length", "Host", "Accept-Encoding"}

type Handler struct {
	Upstream *url.URL
	Provider Provider
	Detector *detect.Detector
	Vault    *vault.Vault
	Client   *http.Client

	// enabled gates whether requests get redacted/restored at all. Toggled
	// at runtime via the control API (serveControl) rather than by
	// stopping the process - env vars only take effect for new agent
	// sessions, so stopping the proxy while ANTHROPIC_BASE_URL/
	// OPENAI_BASE_URL is still set would break the agent's connectivity
	// instead of just turning off protection. Defaults to true; see New.
	enabled atomic.Bool
}

func New(upstream *url.URL, provider Provider, d *detect.Detector, v *vault.Vault) *Handler {
	h := &Handler{Upstream: upstream, Provider: provider, Detector: d, Vault: v, Client: http.DefaultClient}
	h.enabled.Store(true)
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, controlPathPrefix) {
		h.serveControl(w, r)
		return
	}

	if !h.enabled.Load() {
		h.servePassthrough(w, r)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRedactRequestBody))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, fmt.Sprintf("request body exceeds %d bytes", maxRedactRequestBody), http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "failed to read request body", http.StatusBadGateway)
		return
	}

	sessionID, redactedBody, err := h.redactRequest(r.Context(), body)
	if err != nil {
		// Not a body shape we understand - forward unmodified rather than
		// fail the request; detection is defense in depth, not a gate.
		sessionID, redactedBody = "", body
	}

	outReq, err := http.NewRequest(r.Method, h.Upstream.String()+r.URL.Path, bytes.NewReader(redactedBody))
	if err != nil {
		http.Error(w, "failed to build upstream request", http.StatusBadGateway)
		return
	}
	outReq.URL.RawQuery = r.URL.RawQuery
	copyHeaders(outReq.Header, r.Header, requestStripHeaders...)

	resp, err := h.Client.Do(outReq)
	if err != nil {
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Content-Length is excluded: restoring placeholders can change the
	// response body's length, so we let the Go server compute framing.
	copyHeaders(w.Header(), resp.Header, "Content-Length")
	w.WriteHeader(resp.StatusCode)

	if isEventStream(resp.Header.Get("Content-Type")) {
		h.Provider.StreamRestore(w, resp.Body, h.Vault, sessionID)
		return
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("cloak: failed reading upstream response: %v", err)
		return
	}
	if sessionID != "" {
		respBody = []byte(h.Vault.Restore(sessionID, string(respBody)))
	}
	w.Write(respBody)
}

// servePassthrough forwards the request and response byte-for-byte with
// no parsing or redaction at all - the deliberate behavior when toggled
// off, so "disabled" really means nothing touches the traffic, not just
// "redaction happens to find nothing".
func (h *Handler) servePassthrough(w http.ResponseWriter, r *http.Request) {
	outReq, err := http.NewRequest(r.Method, h.Upstream.String()+r.URL.Path, r.Body)
	if err != nil {
		http.Error(w, "failed to build upstream request", http.StatusBadGateway)
		return
	}
	outReq.URL.RawQuery = r.URL.RawQuery
	outReq.ContentLength = r.ContentLength
	copyHeaders(outReq.Header, r.Header, requestStripHeaders...)

	resp, err := h.Client.Do(outReq)
	if err != nil {
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)

	dst := io.Writer(w)
	if flusher, ok := w.(http.Flusher); ok {
		dst = flushWriter{w: w, flusher: flusher}
	}
	io.Copy(dst, resp.Body)
}

// flushWriter flushes after every write so a passed-through SSE stream
// still arrives incrementally instead of buffering until the response
// closes.
type flushWriter struct {
	w       io.Writer
	flusher http.Flusher
}

func (fw flushWriter) Write(p []byte) (int, error) {
	n, err := fw.w.Write(p)
	fw.flusher.Flush()
	return n, err
}

// serveControl handles the runtime toggle API: GET status is read-only;
// enable/disable/toggle require POST since they change state. This is
// loopback-only (the default listen address) and unauthenticated by
// design - the trust boundary is the same as the rest of cloak: whoever
// can already reach localhost on this account can read your terminal
// session anyway.
func (h *Handler) serveControl(w http.ResponseWriter, r *http.Request) {
	switch action := strings.TrimPrefix(r.URL.Path, controlPathPrefix); action {
	case "status":
		h.writeControlStatus(w)
	case "enable", "disable", "toggle":
		if r.Method != http.MethodPost {
			http.Error(w, "use POST", http.StatusMethodNotAllowed)
			return
		}
		switch action {
		case "enable":
			h.enabled.Store(true)
		case "disable":
			h.enabled.Store(false)
		case "toggle":
			for {
				old := h.enabled.Load()
				if h.enabled.CompareAndSwap(old, !old) {
					break
				}
			}
		}
		h.writeControlStatus(w)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) writeControlStatus(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"enabled":%v,"provider":%q}`, h.enabled.Load(), h.Provider.Name())
}

func (h *Handler) redactRequest(ctx context.Context, body []byte) (sessionID string, out []byte, err error) {
	var parsed map[string]interface{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", nil, err
	}

	sessionID = combineSessionID(connID(ctx), h.Provider.DeriveSessionID(parsed))

	redacted := redactJSON(parsed, func(s string) string {
		return redactText(h.Detector, h.Vault, sessionID, s)
	})

	out, err = json.Marshal(redacted)
	return sessionID, out, err
}

// combineSessionID mixes a request's TCP connection identity into its
// content-derived id (see ConnContext in connid.go) so two different
// connections can never collide into the same vault bucket, even with
// byte-identical content.
func combineSessionID(connID uint64, contentID string) string {
	h := sha256.New()
	fmt.Fprintf(h, "%d:", connID)
	h.Write([]byte(contentID))
	return hex.EncodeToString(h.Sum(nil))
}

func copyHeaders(dst, src http.Header, exclude ...string) {
	for k, vals := range src {
		if containsFold(exclude, k) {
			continue
		}
		for _, v := range vals {
			dst.Add(k, v)
		}
	}
}

func containsFold(list []string, s string) bool {
	for _, item := range list {
		if strings.EqualFold(item, s) {
			return true
		}
	}
	return false
}

func isEventStream(contentType string) bool {
	return strings.HasPrefix(contentType, "text/event-stream")
}
