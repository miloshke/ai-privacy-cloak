//go:build linux

package service

import (
	"os/exec"
	"testing"
	"time"
)

// TestInstallStartsStopsRealSystemdUserService exercises the actual
// systemd --user mechanism end to end on a real Linux machine: installs
// a real cloak binary as a background service, confirms it's genuinely
// running and reachable, then uninstalls and confirms it stops - not
// just that the Go code cross-compiles for linux (which is all this path
// had ever been checked against before).
func TestInstallStartsStopsRealSystemdUserService(t *testing.T) {
	if out, err := exec.Command("systemctl", "--user", "daemon-reload").CombinedOutput(); err != nil {
		t.Skipf("no usable systemd --user session in this environment, skipping: %v: %s", err, out)
	}

	bin := buildCloakBinary(t)
	defer setExecutablePath(bin)()

	const listen = "127.0.0.1:18787"
	installMsg, err := Install([]string{"-listen", listen})
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	t.Logf("Install: %s", installMsg)
	defer Uninstall()

	if !waitForHealthy(t, listen, 10*time.Second) {
		statusOut, _ := exec.Command("systemctl", "--user", "status", serviceName).CombinedOutput()
		journal, _ := exec.Command("journalctl", "--user", "-u", serviceName, "--no-pager").CombinedOutput()
		t.Fatalf("installed service never became reachable at %s\nsystemctl status:\n%s\njournal:\n%s", listen, statusOut, journal)
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

	time.Sleep(500 * time.Millisecond)
	if waitForHealthy(t, listen, time.Millisecond) {
		t.Fatalf("expected %s to stop responding after Uninstall", listen)
	}

	if status, err := Status(); err != nil || status != "Not installed." {
		t.Fatalf(`expected Status() == "Not installed." after Uninstall, got %q, err %v`, status, err)
	}
}
