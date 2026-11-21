package proxy

import (
	"strings"

	"cloak/internal/detect"
	"cloak/internal/vault"
)

// redactText replaces every detected match in text with a vault-backed
// placeholder, preserving everything in between untouched.
func redactText(d *detect.Detector, v *vault.Vault, sessionID, text string) string {
	matches := d.Scan(text)
	if len(matches) == 0 {
		return text
	}
	var b strings.Builder
	last := 0
	for _, m := range matches {
		b.WriteString(text[last:m.Start])
		b.WriteString(v.Put(sessionID, string(m.Kind), m.Value))
		last = m.End
	}
	b.WriteString(text[last:])
	return b.String()
}

// structuralKeys are JSON fields that are always protocol metadata, never
// free-text content a user or model wrote: message/tool-call IDs, type
// discriminators, roles. These routinely look like opaque high-entropy
// strings to the detector - a real Anthropic tool_use id or OpenAI
// tool_call id can easily clear the HIGH_ENTROPY_SECRET threshold - but
// providers validate their exact format strictly (Anthropic requires
// tool_use.id to match ^[a-zA-Z0-9_-]+$, for example). Swapping one for
// a "{{...}}" placeholder - which contains characters that pattern
// forbids - doesn't just fail to protect something, it makes the
// provider reject the entire request with a 400. Redacting content
// fields (text, arguments, ...) is the whole point of this proxy;
// redacting structural fields is only ever harmful, so they're always
// skipped regardless of what they look like.
//
// Known residual tradeoff: this skips any field with one of these exact
// names anywhere in the tree, including inside tool-call arguments - so
// a secret that happened to be nested under a key literally named "id"
// or "type" inside arbitrary tool-call JSON would not get caught. That's
// a narrow, unusual shape; breaking every tool call outright is the far
// more common and far more severe failure mode this trades away.
var structuralKeys = map[string]bool{
	"id":            true,
	"tool_use_id":   true, // Anthropic: tool_result's back-reference to the originating tool_use.id
	"tool_call_id":  true, // OpenAI: same concept, different field name
	"type":          true,
	"role":          true,
	"model":         true,
	"object":        true,
	"finish_reason": true,
	"finishReason":  true,
	"stop_reason":   true,
	"signature":     true, // Anthropic extended-thinking blocks: a cryptographic signature over the thinking content, not text anyone wrote - mangling it breaks the signature the API/client verifies against
}

// redactJSON walks an arbitrary decoded JSON value and runs redact over
// every string leaf it finds, except structuralKeys. This makes
// redaction protocol-transparent: it doesn't need to know any particular
// provider's exact request shape, so new fields (tool results, future
// message types) are covered automatically regardless of which Provider
// is in use.
func redactJSON(v interface{}, redact func(string) string) interface{} {
	switch t := v.(type) {
	case string:
		return redact(t)
	case []interface{}:
		out := make([]interface{}, len(t))
		for i, e := range t {
			out[i] = redactJSON(e, redact)
		}
		return out
	case map[string]interface{}:
		out := make(map[string]interface{}, len(t))
		for k, e := range t {
			if structuralKeys[k] {
				out[k] = e
				continue
			}
			out[k] = redactJSON(e, redact)
		}
		return out
	default:
		return t
	}
}
