package proxy

import (
	"testing"
	"time"

	"cloak/internal/detect"
	"cloak/internal/vault"
)

func TestRedactThenRestoreRoundTrips(t *testing.T) {
	d := detect.New()
	v := vault.New(time.Minute)
	sessionID := "test-session"

	original := "here is my key AKIAABCDEFGHIJKLMNOP for the deploy script"

	redacted := redactText(d, v, sessionID, original)
	if redacted == original {
		t.Fatalf("expected the AWS key to be redacted, got unchanged text: %q", redacted)
	}

	restored := v.Restore(sessionID, redacted)
	if restored != original {
		t.Errorf("round trip mismatch:\n original: %q\n restored: %q", original, restored)
	}
}

func TestRedactJSONWalksNestedStructures(t *testing.T) {
	d := detect.New()
	v := vault.New(time.Minute)
	sessionID := "test-session-2"

	input := map[string]interface{}{
		"messages": []interface{}{
			map[string]interface{}{
				"role":    "user",
				"content": "my email is jane@example.com",
			},
		},
	}

	redacted := redactJSON(input, func(s string) string {
		return redactText(d, v, sessionID, s)
	})

	out := redacted.(map[string]interface{})
	messages := out["messages"].([]interface{})
	first := messages[0].(map[string]interface{})
	content := first["content"].(string)

	if content == "my email is jane@example.com" {
		t.Errorf("expected nested content to be redacted, got unchanged text: %q", content)
	}

	restored := v.Restore(sessionID, content)
	if restored != "my email is jane@example.com" {
		t.Errorf("restore mismatch: got %q", restored)
	}
}
