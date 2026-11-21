//go:build linux

package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const serviceName = "cloak.service"

func unitPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "systemd", "user", serviceName), nil
}

// Install writes a systemd --user unit and enables+starts it immediately.
// Restart=on-failure keeps it running if it crashes. Note: a user service
// normally only runs while the user is logged in - see the linger tip
// below for starting it at boot instead.
func Install(args []string) (string, error) {
	exePath, err := executablePath()
	if err != nil {
		return "", fmt.Errorf("resolving executable path: %w", err)
	}
	path, err := unitPath()
	if err != nil {
		return "", err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", fmt.Errorf("creating systemd user directory: %w", err)
	}
	if err := os.WriteFile(path, []byte(systemdUnit(exePath, args)), 0o644); err != nil {
		return "", fmt.Errorf("writing %s: %w", path, err)
	}

	if out, err := exec.Command("systemctl", "--user", "daemon-reload").CombinedOutput(); err != nil {
		return "", fmt.Errorf("systemctl daemon-reload failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("systemctl", "--user", "enable", "--now", serviceName).CombinedOutput(); err != nil {
		return "", fmt.Errorf("systemctl enable failed: %v: %s", err, strings.TrimSpace(string(out)))
	}

	return fmt.Sprintf(
		"Installed and started as a systemd user service (%s).\nUnit: %s\nLogs: journalctl --user -u %s -f\nTip: run `loginctl enable-linger $USER` so it also starts before you log in, not just after.",
		serviceName, path, serviceName,
	), nil
}

func Uninstall() (string, error) {
	path, err := unitPath()
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return "Not installed - nothing to do.", nil
	}

	_ = exec.Command("systemctl", "--user", "disable", "--now", serviceName).Run()
	if err := os.Remove(path); err != nil {
		return "", fmt.Errorf("removing %s: %w", path, err)
	}
	_ = exec.Command("systemctl", "--user", "daemon-reload").Run()
	return fmt.Sprintf("Stopped and removed the systemd user service (%s).", serviceName), nil
}

func Status() (string, error) {
	path, err := unitPath()
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return "Not installed.", nil
	}

	out, _ := exec.Command("systemctl", "--user", "is-active", serviceName).CombinedOutput()
	return fmt.Sprintf("Installed (%s). Active: %s", path, strings.TrimSpace(string(out))), nil
}

func systemdUnit(execPath string, args []string) string {
	full := append([]string{execPath, "serve"}, args...)
	quoted := make([]string, len(full))
	for i, a := range full {
		quoted[i] = systemdQuote(a)
	}
	return fmt.Sprintf(`[Unit]
Description=cloak local secrets/PII proxy

[Service]
ExecStart=%s
Restart=on-failure

[Install]
WantedBy=default.target
`, strings.Join(quoted, " "))
}

// systemdQuote wraps an argument in double quotes if it contains
// whitespace, matching systemd's own ExecStart= quoting rules.
func systemdQuote(s string) string {
	if strings.ContainsAny(s, " \t") {
		return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
	}
	return s
}
