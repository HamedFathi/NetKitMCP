// Package curlparse converts a pasted curl command line into the arguments
// of netkit's HTTP tools. It understands POSIX shell quoting (including
// $'...' ANSI-C strings and backslash line continuations), Windows cmd
// quoting with ^ escapes and continuations, and PowerShell backtick
// continuations. It never executes anything.
package curlparse

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Tokenize splits a command line into arguments. The quoting dialect is
// detected: Windows cmd when the text uses ^ continuations or ^" escapes,
// POSIX shell otherwise (PowerShell backtick continuations are accepted).
func Tokenize(cmd string) ([]string, error) {
	cmd = strings.ReplaceAll(cmd, "\r\n", "\n")
	// Pasted commands often carry trailing blanks after a line
	// continuation ("\ ", "^ ", "` "); a shell would end the command there,
	// but the intent is clearly a continuation.
	cmd = trailingBlanks.ReplaceAllString(cmd, "$1\n")
	if isCmdStyle(cmd) {
		return tokenizeCmd(cmd)
	}
	// PowerShell line continuation: a backtick at the end of a line.
	cmd = strings.ReplaceAll(cmd, "`\n", " ")
	return tokenizePOSIX(cmd)
}

var trailingBlanks = regexp.MustCompile("([\\\\^`])[ \t]+\n")

func isCmdStyle(s string) bool {
	return strings.Contains(s, "^\n") || strings.Contains(s, `^"`) || strings.HasSuffix(strings.TrimSpace(s), "^")
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

// tokenizePOSIX implements the subset of sh word splitting used in curl
// commands: '...', "...", $'...', backslash escapes and continuations, and
// # comments at the start of a word.
func tokenizePOSIX(s string) ([]string, error) {
	var out []string
	var cur strings.Builder
	inTok := false
	emit := func() {
		if inTok {
			out = append(out, cur.String())
			cur.Reset()
			inTok = false
		}
	}
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case isSpace(c):
			emit()
			i++
		case c == '#' && !inTok:
			for i < len(s) && s[i] != '\n' {
				i++
			}
		case c == '\\':
			if i+1 >= len(s) {
				i++
				continue
			}
			if s[i+1] == '\n' {
				i += 2 // line continuation
				continue
			}
			cur.WriteByte(s[i+1])
			inTok = true
			i += 2
		case c == '\'':
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				return nil, errors.New("unterminated single quote")
			}
			cur.WriteString(s[i+1 : i+1+j])
			inTok = true
			i += j + 2
		case c == '$' && i+1 < len(s) && s[i+1] == '\'':
			n, err := ansiC(s[i+2:], &cur)
			if err != nil {
				return nil, err
			}
			inTok = true
			i += 2 + n
		case c == '$' && i+1 < len(s) && s[i+1] == '"':
			i++ // $"..." is a locale string; treat as "..."
		case c == '"':
			i++
			closed := false
			for i < len(s) {
				ch := s[i]
				if ch == '"' {
					closed = true
					i++
					break
				}
				if ch == '\\' && i+1 < len(s) && strings.IndexByte("$`\"\\\n", s[i+1]) >= 0 {
					if s[i+1] != '\n' {
						cur.WriteByte(s[i+1])
					}
					i += 2
					continue
				}
				cur.WriteByte(ch)
				i++
			}
			if !closed {
				return nil, errors.New("unterminated double quote")
			}
			inTok = true
		default:
			cur.WriteByte(c)
			inTok = true
			i++
		}
	}
	emit()
	return out, nil
}

// ansiC decodes the body of a $'...' string starting after the opening
// quote. It returns the number of bytes consumed including the closing quote.
func ansiC(s string, out *strings.Builder) (int, error) {
	i := 0
	for i < len(s) {
		c := s[i]
		if c == '\'' {
			return i + 1, nil
		}
		if c != '\\' || i+1 >= len(s) {
			out.WriteByte(c)
			i++
			continue
		}
		e := s[i+1]
		i += 2
		switch e {
		case 'n':
			out.WriteByte('\n')
		case 't':
			out.WriteByte('\t')
		case 'r':
			out.WriteByte('\r')
		case 'a':
			out.WriteByte(7)
		case 'b':
			out.WriteByte(8)
		case 'e', 'E':
			out.WriteByte(27)
		case 'f':
			out.WriteByte('\f')
		case 'v':
			out.WriteByte('\v')
		case '\\', '\'', '"', '?':
			out.WriteByte(e)
		case 'x':
			n := hexRun(s[i:], 2)
			if n == 0 {
				out.WriteString(`\x`)
				continue
			}
			v, _ := strconv.ParseUint(s[i:i+n], 16, 8)
			out.WriteByte(byte(v))
			i += n
		case 'u', 'U':
			max := 4
			if e == 'U' {
				max = 8
			}
			n := hexRun(s[i:], max)
			if n == 0 {
				out.WriteByte('\\')
				out.WriteByte(e)
				continue
			}
			v, _ := strconv.ParseUint(s[i:i+n], 16, 32)
			r := rune(v)
			if !utf8.ValidRune(r) {
				r = utf8.RuneError
			}
			out.WriteRune(r)
			i += n
		case 'c':
			if i < len(s) {
				out.WriteByte(s[i] & 0x1f)
				i++
			}
		default:
			if e >= '0' && e <= '7' {
				j := i - 1
				n := 0
				for n < 3 && j+n < len(s) && s[j+n] >= '0' && s[j+n] <= '7' {
					n++
				}
				v, _ := strconv.ParseUint(s[j:j+n], 8, 16)
				out.WriteByte(byte(v))
				i = j + n
				continue
			}
			out.WriteByte('\\')
			out.WriteByte(e)
		}
	}
	return 0, errors.New("unterminated $'...' string")
}

func hexRun(s string, max int) int {
	n := 0
	for n < max && n < len(s) && strings.IndexByte("0123456789abcdefABCDEF", s[n]) >= 0 {
		n++
	}
	return n
}

// tokenizeCmd handles Windows cmd.exe text: ^ escapes (outside quotes) and
// ^ line continuations are resolved first, then the arguments are split
// with the MSVC runtime rules curl.exe uses.
func tokenizeCmd(s string) ([]string, error) {
	var pre strings.Builder
	inQ := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '^' && !inQ {
			if i+1 < len(s) {
				if s[i+1] == '\n' {
					pre.WriteByte(' ')
				} else {
					pre.WriteByte(s[i+1])
				}
				i++
			}
			continue
		}
		if c == '"' {
			inQ = !inQ
		}
		pre.WriteByte(c)
	}
	return splitMSVC(pre.String())
}

// splitMSVC splits like CommandLineToArgvW: 2n backslashes before a quote
// give n backslashes and toggle quoting; 2n+1 give n backslashes and a
// literal quote; "" inside quotes is a literal quote.
func splitMSVC(s string) ([]string, error) {
	var out []string
	var cur strings.Builder
	inTok, inQ := false, false
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case isSpace(c) && !inQ:
			if inTok {
				out = append(out, cur.String())
				cur.Reset()
				inTok = false
			}
			i++
		case c == '\\':
			n := 0
			for i+n < len(s) && s[i+n] == '\\' {
				n++
			}
			if i+n < len(s) && s[i+n] == '"' {
				cur.WriteString(strings.Repeat(`\`, n/2))
				if n%2 == 1 {
					cur.WriteByte('"')
					i += n + 1
				} else {
					i += n // the quote is handled next
				}
			} else {
				cur.WriteString(strings.Repeat(`\`, n))
				i += n
			}
			inTok = true
		case c == '"':
			if inQ && i+1 < len(s) && s[i+1] == '"' {
				cur.WriteByte('"')
				i += 2
			} else {
				inQ = !inQ
				i++
			}
			inTok = true
		default:
			cur.WriteByte(c)
			inTok = true
			i++
		}
	}
	if inQ {
		return nil, fmt.Errorf("unterminated double quote")
	}
	if inTok {
		out = append(out, cur.String())
	}
	return out, nil
}
