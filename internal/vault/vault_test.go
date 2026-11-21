package vault

import (
	"sync"
	"testing"
	"time"
)

func TestPutThenRestoreRoundTrips(t *testing.T) {
	v := New(time.Minute)
	placeholder := v.Put("session-1", "AWS_ACCESS_KEY", "AKIAABCDEFGHIJKLMNOP")

	restored := v.Restore("session-1", "the key is "+placeholder)
	if restored != "the key is AKIAABCDEFGHIJKLMNOP" {
		t.Errorf("unexpected restore result: %q", restored)
	}
}

func TestRestoreOnUnknownSessionReturnsTextUnchanged(t *testing.T) {
	v := New(time.Minute)
	text := "nothing to restore here, {{NOT_A_REAL_PLACEHOLDER}}"
	if got := v.Restore("never-seen-session", text); got != text {
		t.Errorf("expected unknown session to pass text through unchanged, got %q", got)
	}
}

func TestPutCounterIncrementsPerSession(t *testing.T) {
	v := New(time.Minute)
	p1 := v.Put("session-1", "EMAIL", "a@example.com")
	p2 := v.Put("session-1", "EMAIL", "b@example.com")
	if p1 == p2 {
		t.Errorf("expected distinct placeholders for two different values in the same session, got %q twice", p1)
	}
}

func TestOnRedactHookReceivesMetadataNeverTheValue(t *testing.T) {
	v := New(time.Minute)

	var mu sync.Mutex
	var gotSession, gotKind, gotPlaceholder string
	v.OnRedact(func(sessionID, kind, placeholder string) {
		mu.Lock()
		defer mu.Unlock()
		gotSession, gotKind, gotPlaceholder = sessionID, kind, placeholder
	})

	placeholder := v.Put("session-1", "AWS_ACCESS_KEY", "AKIAABCDEFGHIJKLMNOP")

	mu.Lock()
	defer mu.Unlock()
	if gotSession != "session-1" || gotKind != "AWS_ACCESS_KEY" || gotPlaceholder != placeholder {
		t.Errorf("hook got (%q, %q, %q), want (%q, %q, %q)", gotSession, gotKind, gotPlaceholder, "session-1", "AWS_ACCESS_KEY", placeholder)
	}
}

func TestOnRedactNilDisablesHook(t *testing.T) {
	v := New(time.Minute)
	called := false
	v.OnRedact(func(string, string, string) { called = true })
	v.OnRedact(nil)

	v.Put("session-1", "EMAIL", "a@example.com")
	if called {
		t.Error("expected no hook call after registering nil")
	}
}
