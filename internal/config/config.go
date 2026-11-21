// Package config resolves the proxy's runtime settings from CLI flags,
// falling back to environment variables and then hardcoded defaults.
package config

import (
	"fmt"
	"net/url"
	"os"
	"time"
)

const (
	DefaultListenAddr        = "127.0.0.1:8787"
	DefaultAnthropicUpstream = "https://api.anthropic.com"
	DefaultOpenAIUpstream    = "https://api.openai.com"
	DefaultGeminiUpstream    = "https://generativelanguage.googleapis.com"
	DefaultSessionTTL        = 30 * time.Minute
)

type Config struct {
	ListenAddr  string
	UpstreamURL *url.URL
	SessionTTL  time.Duration
}

// Load resolves flags against environment variables and then
// defaultUpstream, which the caller picks based on the selected provider
// (there's no single sensible upstream default once more than one
// provider is supported).
func Load(listenAddr, upstream, defaultUpstream string) (*Config, error) {
	if listenAddr == "" {
		listenAddr = envOr("CLOAK_LISTEN_ADDR", DefaultListenAddr)
	}
	if upstream == "" {
		upstream = envOr("CLOAK_UPSTREAM", defaultUpstream)
	}
	u, err := url.Parse(upstream)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream URL %q: %w", upstream, err)
	}
	return &Config{
		ListenAddr:  listenAddr,
		UpstreamURL: u,
		SessionTTL:  DefaultSessionTTL,
	}, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
