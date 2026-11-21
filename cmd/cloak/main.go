// cloak is a local proxy that sits between AI coding agents (Claude Code,
// Cursor, aider, ...) and a model provider's API (Anthropic, OpenAI),
// redacting secrets and PII before they leave the machine and restoring
// them in the response.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"cloak/internal/audit"
	"cloak/internal/bench"
	"cloak/internal/config"
	"cloak/internal/detect"
	"cloak/internal/install"
	"cloak/internal/proxy"
	"cloak/internal/service"
	"cloak/internal/vault"
)

// version is set at build time via -ldflags "-X main.version=vX.Y.Z" by
// the release workflow; a plain `go build`/`go run` leaves it as "dev".
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "serve":
		runServe(os.Args[2:])
	case "install":
		runInstall(os.Args[2:])
	case "bench":
		runBench(os.Args[2:])
	case "service":
		runService(os.Args[2:])
	case "toggle":
		runControlCommand(os.Args[2:], "toggle", http.MethodPost)
	case "enable":
		runControlCommand(os.Args[2:], "enable", http.MethodPost)
	case "disable":
		runControlCommand(os.Args[2:], "disable", http.MethodPost)
	case "protection-status":
		runControlCommand(os.Args[2:], "status", http.MethodGet)
	case "version", "-v", "--version":
		fmt.Println("cloak " + version)
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "cloak: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Println(`cloak - a local secrets/PII firewall for AI coding agents

Usage:
  cloak serve [flags]                Start the proxy in the foreground
  cloak install [flags]              Wire the right base-URL env var into your shell profile
  cloak service install [flags]      Run cloak in the background automatically (survives reboots)
  cloak service uninstall            Remove the background registration
  cloak service status               Check whether the background service is installed/running
  cloak toggle [flags]               Flip redaction on/off on an already-running cloak (doesn't stop it)
  cloak enable [flags]                Turn redaction on
  cloak disable [flags]               Turn redaction off (traffic still flows, just unprotected)
  cloak protection-status [flags]     Check whether a running cloak is currently redacting
  cloak bench [flags]                Run the leak-corpus detection benchmark
  cloak version                      Print the version

"service status" asks the OS whether cloak is registered to run in the background.
"protection-status" asks an already-running cloak whether redaction is currently on - different things.

Flags for serve and service install:
  -provider string    Upstream provider: anthropic, openai, or gemini (default anthropic)
  -listen string       Address to listen on (default 127.0.0.1:8787)
  -upstream string     Upstream API base URL (default depends on -provider)
  -audit-log string    Append a JSON-lines record of every redaction to this file: timestamp,
                        session id, and which kind of thing was redacted - never the real value.
                        Off by default; cloak writes nothing to disk unless you pass this.

Flags for toggle, enable, disable, protection-status:
  -listen string   Address cloak serve is listening on (default 127.0.0.1:8787)

Flags for install:
  -provider string   Which provider's base-URL env var to set: anthropic, openai, or gemini (default anthropic)
  -listen string      Address cloak will listen on (default 127.0.0.1:8787)
  -yes                Actually write to the shell profile (default is a dry-run preview)

Note: cloak service install needs a real binary (go build -o cloak ./cmd/cloak), not go run - it
registers the running executable's own path to relaunch on login, and go run's binary is temporary.`)
}

// providerByName resolves the -provider flag to a Provider implementation
// and the upstream it talks to by default. There's deliberately no "auto"
// mode: one cloak process proxies one provider's wire protocol at a time,
// since the request/response shapes differ enough that guessing would be
// fragile - run a second instance on another port for a second provider.
func providerByName(name string) (proxy.Provider, string, error) {
	switch name {
	case "", "anthropic":
		return proxy.AnthropicProvider{}, config.DefaultAnthropicUpstream, nil
	case "openai":
		return proxy.OpenAIProvider{}, config.DefaultOpenAIUpstream, nil
	case "gemini":
		return proxy.GeminiProvider{}, config.DefaultGeminiUpstream, nil
	default:
		return nil, "", fmt.Errorf("unknown -provider %q (want \"anthropic\", \"openai\", or \"gemini\")", name)
	}
}

func runServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	providerName := fs.String("provider", "anthropic", "upstream provider: anthropic, openai, or gemini")
	listen := fs.String("listen", "", "address to listen on")
	upstream := fs.String("upstream", "", "upstream API base URL")
	auditLogPath := fs.String("audit-log", "", "append JSON-lines redaction metadata (never values) to this file")
	fs.Parse(args)

	provider, defaultUpstream, err := providerByName(*providerName)
	if err != nil {
		log.Fatalf("cloak: %v", err)
	}

	cfg, err := config.Load(*listen, *upstream, defaultUpstream)
	if err != nil {
		log.Fatalf("cloak: %v", err)
	}

	detector := detect.New()
	sessions := vault.New(cfg.SessionTTL)

	var auditLogger *audit.Logger
	if *auditLogPath != "" {
		auditLogger, err = audit.Open(*auditLogPath)
		if err != nil {
			log.Fatalf("cloak: %v", err)
		}
		defer auditLogger.Close()
		sessions.OnRedact(auditLogger.Record)
		log.Printf("cloak: recording redaction metadata (never values) to %s", *auditLogPath)
	}

	handler := proxy.New(cfg.UpstreamURL, provider, detector, sessions)
	// ConnContext ties session identity to the underlying TCP connection
	// in addition to request content, so two unrelated conversations
	// that happen to open with identical text can't collide into the
	// same vault bucket - see combineSessionID in internal/proxy/proxy.go.
	server := &http.Server{Addr: cfg.ListenAddr, Handler: handler, ConnContext: proxy.ConnContext}

	log.Printf("cloak: listening on %s, forwarding to %s (%s)", cfg.ListenAddr, cfg.UpstreamURL, provider.Name())
	log.Printf("cloak: point your agent at it with %s=http://%s", baseURLEnvVar(provider.Name()), cfg.ListenAddr)

	serverErr := make(chan error, 1)
	go func() { serverErr <- server.ListenAndServe() }()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-serverErr:
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("cloak: server error: %v", err)
		}
	case s := <-sig:
		// launchd/systemd send SIGTERM to stop a managed service; drain
		// in-flight requests instead of cutting them off mid-response.
		log.Printf("cloak: received %s, shutting down gracefully", s)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("cloak: graceful shutdown timed out, forcing close: %v", err)
			server.Close()
		}
	}
}

func baseURLEnvVar(providerName string) string {
	switch providerName {
	case "openai":
		return "OPENAI_BASE_URL"
	case "gemini":
		// Google's own Gemini CLI honors this one; third-party coding
		// agents vary in whether they expose a Gemini endpoint override
		// at all, unlike the near-universal ANTHROPIC_BASE_URL/
		// OPENAI_BASE_URL convention - check your specific tool's docs.
		return "GOOGLE_GEMINI_BASE_URL"
	default:
		return "ANTHROPIC_BASE_URL"
	}
}

func runInstall(args []string) {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	providerName := fs.String("provider", "anthropic", "which provider's base-URL env var to set: anthropic, openai, or gemini")
	listen := fs.String("listen", config.DefaultListenAddr, "address cloak will listen on")
	yes := fs.Bool("yes", false, "actually write to the shell profile (default is a dry-run preview)")
	fs.Parse(args)

	if _, _, err := providerByName(*providerName); err != nil {
		log.Fatalf("cloak: %v", err)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("cloak: could not determine home directory: %v", err)
	}
	shell := install.DetectShell(os.Getenv("SHELL"), home)
	value := fmt.Sprintf("http://%s", *listen)
	envVar := baseURLEnvVar(*providerName)

	res, err := install.Apply(shell, envVar, value, !*yes)
	if err != nil {
		log.Fatalf("cloak: %v", err)
	}

	switch {
	case res.AlreadyPresent:
		fmt.Printf("%s already has this line - nothing to do:\n\n  %s\n", res.RCFile, res.Line)
	case *yes:
		fmt.Printf("Added to %s:\n\n  %s\n\nRestart your shell (or run `source %s`), then start the proxy with: cloak serve -provider %s\n", res.RCFile, res.Line, res.RCFile, *providerName)
	default:
		fmt.Printf("Dry run - would append to %s (detected shell: %s):\n\n  %s\n\nRe-run with -yes to actually write it.\n", res.RCFile, shell.Name, res.Line)
	}
}

func runService(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "cloak: usage: cloak service install|uninstall|status [flags]")
		os.Exit(1)
	}
	sub, rest := args[0], args[1:]

	switch sub {
	case "install":
		runServiceInstall(rest)
	case "uninstall":
		msg, err := service.Uninstall()
		if err != nil {
			log.Fatalf("cloak: %v", err)
		}
		fmt.Println(msg)
	case "status":
		msg, err := service.Status()
		if err != nil {
			log.Fatalf("cloak: %v", err)
		}
		fmt.Println(msg)
	default:
		log.Fatalf("cloak: unknown `cloak service` subcommand %q (want install, uninstall, or status)", sub)
	}
}

func runServiceInstall(args []string) {
	fs := flag.NewFlagSet("service install", flag.ExitOnError)
	providerName := fs.String("provider", "anthropic", "upstream provider: anthropic, openai, or gemini")
	listen := fs.String("listen", "", "address to listen on")
	upstream := fs.String("upstream", "", "upstream API base URL")
	auditLogPath := fs.String("audit-log", "", "append JSON-lines redaction metadata (never values) to this file")
	fs.Parse(args)

	if _, _, err := providerByName(*providerName); err != nil {
		log.Fatalf("cloak: %v", err)
	}

	exePath, err := os.Executable()
	if err != nil {
		log.Fatalf("cloak: could not determine executable path: %v", err)
	}
	if service.IsTempBuildBinary(exePath) {
		log.Fatalf("cloak: refusing to install a background service pointing at a temporary `go run` binary (%s).\nBuild a real binary first: go build -o cloak ./cmd/cloak && ./cloak service install", exePath)
	}

	var serveArgs []string
	serveArgs = append(serveArgs, "-provider", *providerName)
	if *listen != "" {
		serveArgs = append(serveArgs, "-listen", *listen)
	}
	if *upstream != "" {
		serveArgs = append(serveArgs, "-upstream", *upstream)
	}
	if *auditLogPath != "" {
		serveArgs = append(serveArgs, "-audit-log", *auditLogPath)
	}

	msg, err := service.Install(serveArgs)
	if err != nil {
		log.Fatalf("cloak: %v", err)
	}
	fmt.Println(msg)
}

// runControlCommand drives an already-running cloak's toggle API over
// HTTP - it's a thin CLI wrapper, not a separate control mechanism, so a
// future menu-bar app and this command stay in sync automatically.
func runControlCommand(args []string, action, method string) {
	fs := flag.NewFlagSet(action, flag.ExitOnError)
	listen := fs.String("listen", config.DefaultListenAddr, "address cloak serve is listening on")
	fs.Parse(args)

	url := fmt.Sprintf("http://%s/__cloak__/%s", *listen, action)
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		log.Fatalf("cloak: %v", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("cloak: could not reach cloak at %s - is `cloak serve` (or `cloak service install`) running?\n%v", *listen, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("cloak: %s failed (%s): %s", action, resp.Status, strings.TrimSpace(string(body)))
	}
	fmt.Println(strings.TrimSpace(string(body)))
}

func runBench(args []string) {
	fs := flag.NewFlagSet("bench", flag.ExitOnError)
	iterations := fs.Int("iterations", 2000, "scans per case for latency measurement")
	fs.Parse(args)

	report := bench.Run(detect.New(), bench.Corpus(), *iterations)
	report.Print(os.Stdout)

	if report.PassedCount() != len(report.Results) {
		os.Exit(1)
	}
}
