package netx

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
)

// StartTLS runs the plaintext upgrade dialogue for smtp, imap, pop3 or ftp
// on conn. When it returns nil the next bytes on conn are the TLS handshake.
// Reads are byte-at-a-time so no handshake bytes are swallowed by a buffer.
func StartTLS(conn net.Conn, proto string) error {
	r := bufio.NewReaderSize(oneByteReader{conn}, 16)
	switch strings.ToLower(proto) {
	case "smtp":
		if _, err := readSMTP(r, "220"); err != nil {
			return fmt.Errorf("smtp greeting: %w", err)
		}
		if err := writeLine(conn, "EHLO netkit-mcp"); err != nil {
			return err
		}
		lines, err := readSMTP(r, "250")
		if err != nil {
			return fmt.Errorf("smtp EHLO: %w", err)
		}
		if !strings.Contains(strings.ToUpper(strings.Join(lines, "\n")), "STARTTLS") {
			return fmt.Errorf("smtp server does not advertise STARTTLS")
		}
		if err := writeLine(conn, "STARTTLS"); err != nil {
			return err
		}
		if _, err := readSMTP(r, "220"); err != nil {
			return fmt.Errorf("smtp STARTTLS: %w", err)
		}
	case "ftp":
		if _, err := readSMTP(r, "220"); err != nil {
			return fmt.Errorf("ftp greeting: %w", err)
		}
		if err := writeLine(conn, "AUTH TLS"); err != nil {
			return err
		}
		if _, err := readSMTP(r, "234"); err != nil {
			return fmt.Errorf("ftp AUTH TLS: %w", err)
		}
	case "imap":
		line, err := readLine(r)
		if err != nil {
			return fmt.Errorf("imap greeting: %w", err)
		}
		if !strings.HasPrefix(strings.ToUpper(line), "* OK") {
			return fmt.Errorf("imap greeting: unexpected %q", line)
		}
		if err := writeLine(conn, "a001 STARTTLS"); err != nil {
			return err
		}
		for {
			line, err := readLine(r)
			if err != nil {
				return fmt.Errorf("imap STARTTLS: %w", err)
			}
			if strings.HasPrefix(line, "*") {
				continue
			}
			if !strings.HasPrefix(strings.ToUpper(line), "A001 OK") {
				return fmt.Errorf("imap STARTTLS refused: %q", line)
			}
			break
		}
	case "pop3":
		line, err := readLine(r)
		if err != nil || !strings.HasPrefix(line, "+OK") {
			return fmt.Errorf("pop3 greeting: %q %v", line, err)
		}
		if err := writeLine(conn, "STLS"); err != nil {
			return err
		}
		line, err = readLine(r)
		if err != nil || !strings.HasPrefix(line, "+OK") {
			return fmt.Errorf("pop3 STLS refused: %q %v", line, err)
		}
	default:
		return fmt.Errorf("unsupported starttls protocol %q (use smtp, imap, pop3 or ftp)", proto)
	}
	return nil
}

type oneByteReader struct{ r io.Reader }

func (o oneByteReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return o.r.Read(p)
}

func writeLine(w io.Writer, s string) error {
	_, err := io.WriteString(w, s+"\r\n")
	return err
}

func readLine(r *bufio.Reader) (string, error) {
	var sb strings.Builder
	for sb.Len() < 4096 {
		b, err := r.ReadByte()
		if err != nil {
			return sb.String(), err
		}
		if b == '\n' {
			return strings.TrimRight(sb.String(), "\r"), nil
		}
		sb.WriteByte(b)
	}
	return sb.String(), fmt.Errorf("line too long")
}

// readSMTP reads a (possibly multi-line) SMTP/FTP reply and checks its code.
func readSMTP(r *bufio.Reader, code string) ([]string, error) {
	var lines []string
	for range 100 {
		line, err := readLine(r)
		if err != nil {
			return lines, err
		}
		lines = append(lines, line)
		if len(line) < 3 {
			return lines, fmt.Errorf("unexpected reply %q", line)
		}
		if line[:3] != code {
			return lines, fmt.Errorf("expected %s, got %q", code, line)
		}
		if len(line) == 3 || line[3] == ' ' {
			return lines, nil
		}
	}
	return lines, fmt.Errorf("reply too long")
}
