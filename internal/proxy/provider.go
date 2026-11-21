package proxy

import (
	"io"
	"net/http"

	"cloak/internal/vault"
)

// Provider captures the parts of a model provider's wire protocol that
// differ enough to need dedicated handling: how to derive a stable
// session key from a decoded request body, and how to restore
// placeholders in a streamed response (every provider frames SSE
// differently). Redaction itself - walking the decoded JSON body and
// replacing matched strings - is protocol-agnostic and shared by every
// provider; see redactJSON/redactText in redact.go.
type Provider interface {
	Name() string
	DeriveSessionID(parsed map[string]interface{}) string
	StreamRestore(w http.ResponseWriter, body io.Reader, v *vault.Vault, sessionID string)
}
