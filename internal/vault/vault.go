// Package vault holds the placeholder -> original-value mapping for each
// in-flight conversation. Entries live only in process memory and are
// purged after an idle timeout - nothing is ever written to disk, which is
// the core trust property of the whole proxy.
package vault

import (
	"strconv"
	"strings"
	"sync"
	"time"
)

type Vault struct {
	mu       sync.Mutex
	sessions map[string]*session
	idleTTL  time.Duration

	// onRedact, if set, fires on every Put - with the session ID, the
	// detected Kind, and the placeholder that replaced it, never the real
	// value. Exists purely so a caller can observe what got redacted
	// (e.g. an opt-in local audit log) without the vault itself knowing
	// anything about logging, files, or disk writes - it stays in-memory
	// only by default, same as always, unless something is registered.
	onRedact func(sessionID, kind, placeholder string)
}

type session struct {
	values     map[string]string // placeholder -> original value
	counter    int
	lastActive time.Time
}

func New(idleTTL time.Duration) *Vault {
	v := &Vault{sessions: make(map[string]*session), idleTTL: idleTTL}
	go v.reap()
	return v
}

// OnRedact registers fn to be called on every subsequent Put, receiving
// only the session ID, the detected Kind, and the placeholder - never the
// real value. Pass nil (the default) to disable it again.
func (v *Vault) OnRedact(fn func(sessionID, kind, placeholder string)) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.onRedact = fn
}

// Put stores original under a freshly minted placeholder for sessionID and
// returns that placeholder to substitute into the outgoing request.
func (v *Vault) Put(sessionID, kind, original string) string {
	v.mu.Lock()
	s := v.sessionFor(sessionID)
	s.counter++
	placeholder := "{{" + kind + "_" + strconv.Itoa(s.counter) + "}}"
	s.values[placeholder] = original
	s.lastActive = time.Now()
	hook := v.onRedact
	v.mu.Unlock()

	if hook != nil {
		hook(sessionID, kind, placeholder)
	}
	return placeholder
}

// Restore swaps every placeholder known for sessionID back to its original
// value. Unknown sessions (nothing was ever redacted) are returned as-is.
func (v *Vault) Restore(sessionID, text string) string {
	v.mu.Lock()
	defer v.mu.Unlock()
	s, ok := v.sessions[sessionID]
	if !ok {
		return text
	}
	s.lastActive = time.Now()
	for placeholder, original := range s.values {
		text = strings.ReplaceAll(text, placeholder, original)
	}
	return text
}

func (v *Vault) sessionFor(id string) *session {
	s, ok := v.sessions[id]
	if !ok {
		s = &session{values: make(map[string]string), lastActive: time.Now()}
		v.sessions[id] = s
	}
	return s
}

func (v *Vault) reap() {
	ticker := time.NewTicker(v.idleTTL / 2)
	defer ticker.Stop()
	for range ticker.C {
		v.mu.Lock()
		for id, s := range v.sessions {
			if time.Since(s.lastActive) > v.idleTTL {
				delete(v.sessions, id)
			}
		}
		v.mu.Unlock()
	}
}
