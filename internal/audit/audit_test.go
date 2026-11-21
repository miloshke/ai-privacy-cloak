package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRecordWritesMetadataNeverTheValue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	realSecret := "AKIAABCDEFGHIJKLMNOP"
	l.Record("session-abc", "AWS_ACCESS_KEY", "{{AWS_ACCESS_KEY_1}}")
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading audit log: %v", err)
	}

	if strings.Contains(string(contents), realSecret) {
		t.Fatalf("audit log must never contain the real value, got: %s", contents)
	}

	var e event
	if err := json.Unmarshal(contents[:len(contents)-1], &e); err != nil { // trim trailing newline
		t.Fatalf("failed to parse audit log line %q: %v", contents, err)
	}
	if e.SessionID != "session-abc" || e.Kind != "AWS_ACCESS_KEY" || e.Placeholder != "{{AWS_ACCESS_KEY_1}}" {
		t.Errorf("unexpected event fields: %+v", e)
	}
	if e.Time == "" {
		t.Error("expected a non-empty timestamp")
	}
}

func TestRecordAppendsMultipleLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer l.Close()

	l.Record("s1", "EMAIL", "{{EMAIL_1}}")
	l.Record("s1", "PHONE", "{{PHONE_1}}")

	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading audit log: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(contents)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d: %q", len(lines), contents)
	}
}

// A natural first choice like ~/.cloak/audit.jsonl has no reason to
// already exist - every existing test above put the file directly in
// t.TempDir(), which already exists, and so never actually exercised
// this. This is exactly the scenario that broke on first real use.
func TestOpenCreatesMissingParentDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "subdir", "audit.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatalf("Open should create missing parent directories, got: %v", err)
	}
	defer l.Close()

	l.Record("s1", "EMAIL", "{{EMAIL_1}}")

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected the audit log file to exist, got: %v", err)
	}
}

func TestOpenCreatesFileWithOwnerOnlyPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		// os.OpenFile's mode argument only controls the read-only
		// attribute on Windows, not a real owner-only ACL - os.Stat
		// reports a synthesized 0666/0444 regardless of what Open asked
		// for, so the 0600 assertion below doesn't mean anything there.
		// Privacy of this file on Windows comes from the user profile
		// directory's own default ACL inheritance, not from this code.
		t.Skip("file permission bits don't map to a real owner-only ACL on Windows")
	}

	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer l.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("expected mode 0600, got %o", perm)
	}
}
