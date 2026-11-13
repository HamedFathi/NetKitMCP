// Package config holds server-wide settings: security policy, limits and
// their hard ceilings. Per-call options may lower a limit freely but can never
// raise it above the ceiling configured here.
package config

import (
	"time"
)

// PrivateMode controls how the SSRF guard treats private/loopback targets.
type PrivateMode string

const (
	// PrivateDeny blocks private targets even when a call sets allow_private.
	PrivateDeny PrivateMode = "deny"
	// PrivateOptIn blocks private targets unless a call sets allow_private=true (default).
	PrivateOptIn PrivateMode = "optin"
	// PrivateAllow permits private targets for every call.
	PrivateAllow PrivateMode = "allow"
)

// Config is the server-wide configuration.
type Config struct {
	// File access.
	AllowReadDirs  []string
	AllowWriteDirs []string

	// Network policy.
	PrivateMode PrivateMode
	AllowHosts  []string // glob patterns; empty = all hosts allowed
	DenyHosts   []string // glob patterns
	AllowPorts  []int    // for raw sockets (tcp/udp/dns); empty = all ports

	// Defaults and ceilings.
	DefaultTimeout       time.Duration
	MaxTimeout           time.Duration
	DefaultResponseBytes int64
	MaxResponseBytes     int64
	DefaultUploadBytes   int64
	MaxUploadBytes       int64
	DefaultDownloadBytes int64
	MaxDownloadBytes     int64
	DefaultMaxRedirects  int
	MaxRedirects         int
	DefaultMaxMessages   int
	MaxMessages          int
	DefaultStreamTime    time.Duration
	MaxStreamTime        time.Duration
	MaxSessions          int
	SessionIdleTTL       time.Duration
	RingBufferSize       int
	MaxInlineBase64Bytes int64

	UserAgent string
}

// Default returns a configuration with conservative defaults.
func Default() *Config {
	return &Config{
		PrivateMode:          PrivateOptIn,
		DefaultTimeout:       30 * time.Second,
		MaxTimeout:           10 * time.Minute,
		DefaultResponseBytes: 1 << 20,  // 1 MiB returned inline
		MaxResponseBytes:     16 << 20, // 16 MiB
		DefaultUploadBytes:   1 << 30,  // 1 GiB
		MaxUploadBytes:       16 << 30, // 16 GiB
		DefaultDownloadBytes: 1 << 30,  // 1 GiB
		MaxDownloadBytes:     16 << 30, // 16 GiB
		DefaultMaxRedirects:  10,
		MaxRedirects:         30,
		DefaultMaxMessages:   100,
		MaxMessages:          10000,
		DefaultStreamTime:    10 * time.Second,
		MaxStreamTime:        10 * time.Minute,
		MaxSessions:          64,
		SessionIdleTTL:       10 * time.Minute,
		RingBufferSize:       1000,
		MaxInlineBase64Bytes: 8 << 20,
		UserAgent:            "netkit-mcp/" + Version,
	}
}

// Version is the server version, overridable at link time.
var Version = "1.0.0"

// Timeout resolves a per-call timeout in seconds against defaults and ceiling.
func (c *Config) Timeout(seconds float64) time.Duration {
	return clampDur(seconds, c.DefaultTimeout, c.MaxTimeout)
}

// StreamDuration resolves a per-call stream duration in seconds.
func (c *Config) StreamDuration(seconds float64) time.Duration {
	return clampDur(seconds, c.DefaultStreamTime, c.MaxStreamTime)
}

// ResponseBytes resolves a per-call max inline response size.
func (c *Config) ResponseBytes(n int64) int64 {
	return clampInt(n, c.DefaultResponseBytes, c.MaxResponseBytes)
}

// UploadBytes resolves a per-call max upload size.
func (c *Config) UploadBytes(n int64) int64 {
	return clampInt(n, c.DefaultUploadBytes, c.MaxUploadBytes)
}

// DownloadBytes resolves a per-call max download size.
func (c *Config) DownloadBytes(n int64) int64 {
	return clampInt(n, c.DefaultDownloadBytes, c.MaxDownloadBytes)
}

// Redirects resolves a per-call max redirect count (0 means default).
func (c *Config) Redirects(n int) int {
	return int(clampInt(int64(n), int64(c.DefaultMaxRedirects), int64(c.MaxRedirects)))
}

// Messages resolves a per-call max message count (0 means default).
func (c *Config) Messages(n int) int {
	return int(clampInt(int64(n), int64(c.DefaultMaxMessages), int64(c.MaxMessages)))
}

func clampDur(seconds float64, def, max time.Duration) time.Duration {
	if seconds <= 0 {
		return def
	}
	d := time.Duration(seconds * float64(time.Second))
	if d > max {
		return max
	}
	return d
}

func clampInt(n, def, max int64) int64 {
	if n <= 0 {
		return def
	}
	if n > max {
		return max
	}
	return n
}
