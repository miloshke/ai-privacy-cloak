// Package service registers cloak to run automatically in the background
// via each OS's native mechanism - a launchd agent on macOS, a systemd
// user service on Linux, a login Run-key entry on Windows - so protection
// survives reboots without a dedicated terminal tab. Each platform's
// Install/Uninstall/Status live in their own build-tagged file; this file
// holds the one bit of logic that's the same everywhere.
package service

import (
	"os"
	"strings"
)

// IsTempBuildBinary reports whether path looks like the throwaway binary
// `go run` compiles to a temp directory (named "go-buildNNNNNN" on every
// platform's toolchain). Installing a service that points at one would
// work until the temp file is cleaned up, then silently stop protecting
// anything - so callers should refuse and ask for a real `go build`
// binary instead.
func IsTempBuildBinary(path string) bool {
	return strings.Contains(path, "go-build")
}

// executablePath resolves the binary that gets registered to run in the
// background. A package-level var, rather than calling os.Executable
// directly, purely so integration tests can substitute a real,
// disposable cloak binary in place of the go test binary itself when
// exercising the actual launchd/systemd/Run-key mechanism end to end.
var executablePath = os.Executable
