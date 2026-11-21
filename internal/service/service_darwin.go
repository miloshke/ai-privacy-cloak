//go:build darwin

package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const launchdLabel = "dev.cloak.proxy"

func plistPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "LaunchAgents", launchdLabel+".plist"), nil
}

func logFilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, "Library", "Logs", "cloak")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("creating log directory: %w", err)
	}
	return filepath.Join(dir, "cloak.log"), nil
}

// Install writes a launchd agent plist and loads it immediately.
// RunAtLoad + KeepAlive mean it starts on login and gets relaunched if it
// crashes, without any GUI or supervision from the user.
func Install(args []string) (string, error) {
	exePath, err := executablePath()
	if err != nil {
		return "", fmt.Errorf("resolving executable path: %w", err)
	}
	path, err := plistPath()
	if err != nil {
		return "", err
	}
	log, err := logFilePath()
	if err != nil {
		return "", err
	}

	fullArgs := append([]string{"serve"}, args...)
	content := launchdPlist(launchdLabel, exePath, fullArgs, log)

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", fmt.Errorf("creating LaunchAgents directory: %w", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return "", fmt.Errorf("writing %s: %w", path, err)
	}

	// Unload first in case it's already installed (e.g. re-running after
	// a flag change) - launchctl load errors on an already-loaded label.
	_ = exec.Command("launchctl", "unload", path).Run()
	if out, err := exec.Command("launchctl", "load", "-w", path).CombinedOutput(); err != nil {
		return "", fmt.Errorf("launchctl load failed: %v: %s", err, strings.TrimSpace(string(out)))
	}

	return fmt.Sprintf("Installed and started as a launchd agent (%s).\nConfig: %s\nLogs: %s", launchdLabel, path, log), nil
}

func Uninstall() (string, error) {
	path, err := plistPath()
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return "Not installed - nothing to do.", nil
	}

	_ = exec.Command("launchctl", "unload", path).Run()
	if err := os.Remove(path); err != nil {
		return "", fmt.Errorf("removing %s: %w", path, err)
	}
	return fmt.Sprintf("Stopped and removed the launchd agent (%s).", launchdLabel), nil
}

func Status() (string, error) {
	path, err := plistPath()
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return "Not installed.", nil
	}

	out, err := exec.Command("launchctl", "list", launchdLabel).CombinedOutput()
	if err != nil {
		return fmt.Sprintf("Installed (%s) but not currently running.", path), nil
	}
	return fmt.Sprintf("Installed and running (%s):\n%s", path, strings.TrimSpace(string(out))), nil
}

func launchdPlist(label, execPath string, args []string, logPath string) string {
	var argsXML strings.Builder
	argsXML.WriteString("\t\t<string>" + escapeXML(execPath) + "</string>\n")
	for _, a := range args {
		argsXML.WriteString("\t\t<string>" + escapeXML(a) + "</string>\n")
	}

	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
%s	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardOutPath</key>
	<string>%s</string>
	<key>StandardErrorPath</key>
	<string>%s</string>
</dict>
</plist>
`, escapeXML(label), argsXML.String(), escapeXML(logPath), escapeXML(logPath))
}

func escapeXML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, `"`, "&quot;")
	s = strings.ReplaceAll(s, "'", "&apos;")
	return s
}
