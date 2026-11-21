package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplyAppendsThenIsIdempotent(t *testing.T) {
	home := t.TempDir()
	shell := DetectShell("/bin/zsh", home)

	res, err := Apply(shell, "ANTHROPIC_BASE_URL", "http://127.0.0.1:8787", false)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Applied || res.AlreadyPresent {
		t.Fatalf("expected first Apply to write the line, got %+v", res)
	}

	contents, err := os.ReadFile(shell.RCFile)
	if err != nil {
		t.Fatalf("reading rc file: %v", err)
	}
	if !strings.Contains(string(contents), "export ANTHROPIC_BASE_URL=http://127.0.0.1:8787") {
		t.Fatalf("rc file missing export line, got: %s", contents)
	}

	res2, err := Apply(shell, "ANTHROPIC_BASE_URL", "http://127.0.0.1:8787", false)
	if err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	if !res2.AlreadyPresent || res2.Applied {
		t.Fatalf("expected second Apply to be a no-op, got %+v", res2)
	}

	contents2, _ := os.ReadFile(shell.RCFile)
	if strings.Count(string(contents2), "ANTHROPIC_BASE_URL") != 1 {
		t.Fatalf("expected exactly one export line after two Apply calls, got: %s", contents2)
	}
}

func TestApplyDryRunWritesNothing(t *testing.T) {
	home := t.TempDir()
	shell := DetectShell("/bin/zsh", home)

	res, err := Apply(shell, "ANTHROPIC_BASE_URL", "http://127.0.0.1:8787", true)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.Applied {
		t.Fatalf("dry-run should not mark Applied, got %+v", res)
	}
	if _, err := os.Stat(shell.RCFile); !os.IsNotExist(err) {
		t.Fatalf("dry-run should not create the rc file, stat err: %v", err)
	}
}

func TestDetectShellFish(t *testing.T) {
	shell := DetectShell("/usr/local/bin/fish", "/home/u")
	if shell.Name != "fish" {
		t.Fatalf("expected fish, got %s", shell.Name)
	}
	want := filepath.Join("/home/u", ".config", "fish", "config.fish")
	if shell.RCFile != want {
		t.Fatalf("expected rc file %s, got %s", want, shell.RCFile)
	}
	if got := shell.ExportLine("KEY", "VAL"); got != "set -gx KEY VAL" {
		t.Fatalf("unexpected fish export syntax: %s", got)
	}
}
