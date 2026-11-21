//go:build windows

package service

import (
	"os/exec"
	"testing"
	"time"
)

// TestInstallStartsStopsRealLoginAutostartEntry exercises the actual
// Windows Run-key mechanism end to end on a real Windows machine:
// installs a real cloak binary to launch on login (and starts it
// immediately, per Install's own behavior), confirms it's genuinely
// running and reachable, then uninstalls and confirms the registry entry
// is gone - not just that the Go code cross-compiles for windows (which
// is all this path had ever been checked against before).
func TestInstallStartsStopsRealLoginAutostartEntry(t *testing.T) {
	bin := buildCloakBinary(t)
	defer setExecutablePath(bin)()

	const listen = "127.0.0.1:18788"
	installMsg, err := Install([]string{"-listen", listen})
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	t.Logf("Install: %s", installMsg)
	// Uninstall only removes the Run-key registration, not the process
	// Install started - documented in Uninstall's own returned message -
	// so kill it explicitly for a clean test regardless of outcome.
	defer exec.Command("taskkill", "/IM", "cloak.exe", "/F").Run()
	defer Uninstall()

	if !waitForHealthy(t, listen, 10*time.Second) {
		t.Fatalf("installed service never became reachable at %s", listen)
	}

	statusMsg, err := Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	t.Logf("Status: %s", statusMsg)

	uninstallMsg, err := Uninstall()
	if err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	t.Logf("Uninstall: %s", uninstallMsg)

	if status, err := Status(); err != nil || status != "Not installed." {
		t.Fatalf(`expected Status() == "Not installed." after Uninstall, got %q, err %v`, status, err)
	}
}
