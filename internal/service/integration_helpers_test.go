package service

import (
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// buildCloakBinary compiles a real cloak binary for the current OS into a
// temp directory, so a service integration test registers and runs
// something that actually works as `cloak serve`, rather than the go
// test binary itself (which doesn't understand the "serve" subcommand
// and would misbehave if ExecStart pointed at it).
func buildCloakBinary(t *testing.T) string {
	t.Helper()

	name := "cloak"
	if runtime.GOOS == "windows" {
		name = "cloak.exe"
	}
	out := filepath.Join(t.TempDir(), name)

	pkgDir, err := filepath.Abs(filepath.Join("..", "..", "cmd", "cloak"))
	if err != nil {
		t.Fatalf("resolving cmd/cloak path: %v", err)
	}

	cmd := exec.Command("go", "build", "-o", out, pkgDir)
	cmd.Env = os.Environ()
	if buildOut, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building cloak binary: %v: %s", err, buildOut)
	}
	return out
}

// setExecutablePath overrides the executablePath seam (service.go) for
// the duration of a test, returning a func that restores it.
func setExecutablePath(path string) func() {
	prev := executablePath
	executablePath = func() (string, error) { return path, nil }
	return func() { executablePath = prev }
}

// waitForHealthy polls cloak's control-API status endpoint until it
// responds or timeout elapses, proving the service that Install
// registered is genuinely running and reachable - not just that the
// install call returned without error.
func waitForHealthy(t *testing.T, listen string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + listen + "/__cloak__/status")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return true
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}
