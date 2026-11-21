// Package install wires cloak into a user's shell profile so their agent
// picks up the proxy automatically on the next shell session.
package install

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const marker = "# added by cloak install"

type Shell struct {
	Name       string
	RCFile     string
	ExportLine func(key, value string) string
}

// DetectShell maps $SHELL to the rc file and export syntax it uses. Fish
// needs `set -gx`, not `export`; anything unrecognized falls back to zsh,
// the macOS default since Catalina.
func DetectShell(shellEnv, home string) Shell {
	switch base := filepath.Base(shellEnv); {
	case strings.Contains(base, "fish"):
		return Shell{
			Name:       "fish",
			RCFile:     filepath.Join(home, ".config", "fish", "config.fish"),
			ExportLine: func(k, v string) string { return fmt.Sprintf("set -gx %s %s", k, v) },
		}
	case strings.Contains(base, "bash"):
		return Shell{
			Name:       "bash",
			RCFile:     filepath.Join(home, ".bashrc"),
			ExportLine: func(k, v string) string { return fmt.Sprintf("export %s=%s", k, v) },
		}
	default:
		return Shell{
			Name:       "zsh",
			RCFile:     filepath.Join(home, ".zshrc"),
			ExportLine: func(k, v string) string { return fmt.Sprintf("export %s=%s", k, v) },
		}
	}
}

// Result describes what Apply did (or would do, in dry-run mode) so the
// caller can report it without Apply itself printing anything.
type Result struct {
	RCFile         string
	Line           string
	AlreadyPresent bool
	Applied        bool
}

// Apply ensures shell's rc file exports key=value, appending a clearly
// marked, easy-to-remove block if it's not already there. It never
// rewrites or removes existing lines - if the file already contains the
// exact export we'd add, it's a no-op; anything else is left untouched.
// If dryRun is true, nothing is written and Result reports what would
// happen.
func Apply(shell Shell, key, value string, dryRun bool) (Result, error) {
	line := shell.ExportLine(key, value)
	res := Result{RCFile: shell.RCFile, Line: line}

	existing, err := os.ReadFile(shell.RCFile)
	if err != nil && !os.IsNotExist(err) {
		return res, fmt.Errorf("reading %s: %w", shell.RCFile, err)
	}

	if strings.Contains(string(existing), line) {
		res.AlreadyPresent = true
		return res, nil
	}
	if dryRun {
		return res, nil
	}

	if err := os.MkdirAll(filepath.Dir(shell.RCFile), 0o755); err != nil {
		return res, fmt.Errorf("creating %s: %w", filepath.Dir(shell.RCFile), err)
	}

	f, err := os.OpenFile(shell.RCFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return res, fmt.Errorf("opening %s: %w", shell.RCFile, err)
	}
	defer f.Close()

	if _, err := fmt.Fprintf(f, "\n%s\n%s\n", marker, line); err != nil {
		return res, fmt.Errorf("writing %s: %w", shell.RCFile, err)
	}

	res.Applied = true
	return res, nil
}
