//go:build windows

package service

import (
	"fmt"
	"os/exec"
	"strings"
	"syscall"
)

const (
	runKeyPath      = `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
	runKeyValueName = "Cloak"
	detachedProcess = 0x00000008
)

// Install registers cloak.exe to launch on login via the Run registry key
// (no admin rights needed, unlike a real Windows Service) and starts it
// immediately so the user doesn't have to log out and back in.
func Install(args []string) (string, error) {
	exePath, err := executablePath()
	if err != nil {
		return "", fmt.Errorf("resolving executable path: %w", err)
	}
	cmdLine := commandLine(exePath, args)

	addCmd := exec.Command("reg", "add", runKeyPath, "/v", runKeyValueName, "/d", cmdLine, "/f")
	if out, err := addCmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("reg add failed: %v: %s", err, strings.TrimSpace(string(out)))
	}

	startCmd := exec.Command(exePath, append([]string{"serve"}, args...)...)
	startCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: detachedProcess}
	if err := startCmd.Start(); err != nil {
		return "", fmt.Errorf("registered to start on login, but failed to start it now: %w", err)
	}

	return fmt.Sprintf("Registered to start on login (%s\\%s) and started now (pid %d).", runKeyPath, runKeyValueName, startCmd.Process.Pid), nil
}

func Uninstall() (string, error) {
	delCmd := exec.Command("reg", "delete", runKeyPath, "/v", runKeyValueName, "/f")
	out, err := delCmd.CombinedOutput()
	if err != nil {
		lower := strings.ToLower(string(out))
		if strings.Contains(lower, "unable to find") || strings.Contains(lower, "cannot find") {
			return "Not installed - nothing to do.", nil
		}
		return "", fmt.Errorf("reg delete failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return fmt.Sprintf(
		"Removed the login auto-start entry (%s). A currently running cloak.exe process, if any, isn't killed automatically - stop it from Task Manager if needed.",
		runKeyValueName,
	), nil
}

func Status() (string, error) {
	queryCmd := exec.Command("reg", "query", runKeyPath, "/v", runKeyValueName)
	out, err := queryCmd.CombinedOutput()
	if err != nil {
		return "Not installed.", nil
	}
	return fmt.Sprintf("Installed:\n%s", strings.TrimSpace(string(out))), nil
}

func commandLine(execPath string, args []string) string {
	parts := make([]string, 0, len(args)+2)
	parts = append(parts, quoteWindowsArg(execPath), "serve")
	for _, a := range args {
		parts = append(parts, quoteWindowsArg(a))
	}
	return strings.Join(parts, " ")
}

func quoteWindowsArg(s string) string {
	if strings.ContainsAny(s, " \t") {
		return `"` + s + `"`
	}
	return s
}
