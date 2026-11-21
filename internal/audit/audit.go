// Package audit implements an opt-in, local, metadata-only log of
// redaction events: when something was redacted, what kind of thing it
// was, and which session - never the real value that triggered it, and
// never the placeholder's mapping back to that value. Nothing here is
// enabled unless a caller explicitly opens a Logger; cloak writes
// nothing to disk by default, and this doesn't change that default, it
// just makes it possible to opt out of it on purpose.
package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Logger struct {
	mu   sync.Mutex
	file *os.File
}

type event struct {
	Time        string `json:"time"`
	SessionID   string `json:"session_id"`
	Kind        string `json:"kind"`
	Placeholder string `json:"placeholder"`
}

// Open appends to path, creating its parent directory (0700 - owner-only)
// and the file itself (0600 - owner-only, since even metadata about what
// a user has had redacted is worth keeping private) if either doesn't
// exist yet. A natural first choice like ~/.cloak/audit.jsonl has no
// reason to already exist, so this has to work on the first run, not
// just when the directory happens to already be there.
func Open(path string) (*Logger, error) {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("creating directory for audit log %s: %w", path, err)
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening audit log %s: %w", path, err)
	}
	return &Logger{file: f}, nil
}

// Record writes one JSON line. sessionID and kind and placeholder are
// exactly the three things vault.Vault's onRedact hook provides - this
// signature exists so it can be passed directly to vault.OnRedact.
func (l *Logger) Record(sessionID, kind, placeholder string) {
	line, err := json.Marshal(event{
		Time:        time.Now().UTC().Format(time.RFC3339),
		SessionID:   sessionID,
		Kind:        kind,
		Placeholder: placeholder,
	})
	if err != nil {
		return
	}
	line = append(line, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()
	l.file.Write(line)
}

func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.file.Close()
}
