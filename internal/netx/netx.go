// Package netx implements the low-level network clients behind the
// "lowlevel" tool group: raw TCP and UDP exchanges, DNS queries over
// UDP/TCP/DoT/DoH and TLS inspection.
//
// The package never dials on its own: callers pass a DialFunc (normally a
// guarded netguard dialer) so the SSRF guard and port allowlist apply.
package netx

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// DialFunc dials a network connection.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Ended-by values for raw exchanges.
const (
	EndedDelimiter  = "delimiter"
	EndedLength     = "length"
	EndedPeerClosed = "peer_closed"
	EndedIdle       = "idle"
	EndedTimeout    = "timeout"
	EndedMaxBytes   = "max_bytes"
	EndedMaxResp    = "max_responses"
	EndedError      = "error"
	EndedNoRead     = "no_read"
)

// Unescape interprets backslash escapes: \r \n \t \0 \a \b \f \v \e \\ \" \'
// \xHH and \uHHHH. Unknown escapes are kept literally.
func Unescape(s string) ([]byte, error) {
	if !strings.Contains(s, `\`) {
		return []byte(s), nil
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' || i+1 >= len(s) {
			out = append(out, c)
			continue
		}
		i++
		switch e := s[i]; e {
		case 'r':
			out = append(out, '\r')
		case 'n':
			out = append(out, '\n')
		case 't':
			out = append(out, '\t')
		case '0':
			out = append(out, 0)
		case 'a':
			out = append(out, 7)
		case 'b':
			out = append(out, 8)
		case 'f':
			out = append(out, '\f')
		case 'v':
			out = append(out, '\v')
		case 'e':
			out = append(out, 0x1b)
		case '\\', '"', '\'':
			out = append(out, e)
		case 'x':
			if len(s)-i-1 < 2 {
				return nil, fmt.Errorf("invalid \\x escape at offset %d (need two hex digits)", i-1)
			}
			v, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
			if err != nil {
				return nil, fmt.Errorf("invalid \\x escape %q", s[i-1:i+3])
			}
			out = append(out, byte(v))
			i += 2
		case 'u':
			if len(s)-i-1 < 4 {
				return nil, fmt.Errorf("invalid \\u escape at offset %d (need four hex digits)", i-1)
			}
			v, err := strconv.ParseUint(s[i+1:i+5], 16, 32)
			if err != nil {
				return nil, fmt.Errorf("invalid \\u escape %q", s[i-1:i+5])
			}
			out = append(out, []byte(string(rune(v)))...)
			i += 4
		default:
			out = append(out, '\\', e)
		}
	}
	return out, nil
}

// ParseHex decodes hex that may contain whitespace, colons, dashes or a 0x
// prefix ("de ad be ef", "de:ad:be:ef", "0xdeadbeef").
func ParseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	clean := strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\n', '\r', ':', '-', '_':
			return -1
		}
		return r
	}, s)
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("invalid hex: %w", err)
	}
	return b, nil
}

// HexDump returns a compact hexdump of at most limit bytes.
func HexDump(b []byte, limit int) string {
	if limit > 0 && len(b) > limit {
		return hex.Dump(b[:limit]) + fmt.Sprintf("... (%d more bytes)\n", len(b)-limit)
	}
	return hex.Dump(b)
}

// MS converts a duration to fractional milliseconds rounded to 0.01.
func MS(d time.Duration) float64 {
	return float64(d.Microseconds()/10) / 100
}

// JoinHostPort joins host and port, defaulting the port when host has none.
// host may already contain a port ("example.com:5353", "[::1]:53").
func JoinHostPort(host string, defPort int) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(strings.Trim(host, "[]"), strconv.Itoa(defPort))
}
