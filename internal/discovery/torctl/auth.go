package torctl

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	cookieLen = 32
	nonceLen  = 32
	serverKey = "Tor safe cookie authentication server-to-controller hash"
	clientKey = "Tor safe cookie authentication controller-to-server hash"
)

// ErrNoUsableAuth: the server offers no method lethe accepts. Plain COOKIE (which hands the cookie
// to whoever listens on the port) and passwords are not used (ADR 0007).
var ErrNoUsableAuth = errors.New("tor control: no supported authentication method (want SAFECOOKIE or NULL)")

// ErrServerHash: the server could not prove it knows the cookie. Nothing derived from the cookie
// was sent.
var ErrServerHash = errors.New("tor control: server hash mismatch")

// ProtocolInfo is the PROTOCOLINFO answer.
type ProtocolInfo struct {
	Methods    []string
	CookieFile string
	Version    string
}

// ProtocolInfo asks which authentication methods the server accepts.
func (c *Conn) ProtocolInfo(ctx context.Context) (ProtocolInfo, error) {
	rep, err := c.Command(ctx, "PROTOCOLINFO 1")
	if err != nil {
		return ProtocolInfo{}, err
	}
	if err := rep.Err(); err != nil {
		return ProtocolInfo{}, err
	}
	var pi ProtocolInfo
	for _, l := range rep.Lines {
		switch {
		case strings.HasPrefix(l.Text, "AUTH "):
			kv := parseKV(l.Text[len("AUTH "):])
			if m := kv["METHODS"]; m != "" {
				pi.Methods = strings.Split(m, ",")
			}
			pi.CookieFile = kv["COOKIEFILE"]
		case strings.HasPrefix(l.Text, "VERSION "):
			pi.Version = parseKV(l.Text[len("VERSION "):])["Tor"]
		}
	}
	return pi, nil
}

// Authenticate runs PROTOCOLINFO and then NULL or SAFECOOKIE authentication. cookiePath "auto"
// (or "") uses the COOKIEFILE the server announces; that path is safe to follow only because
// SAFECOOKIE never reveals the file to a server that does not already know it.
func (c *Conn) Authenticate(ctx context.Context, cookiePath string) error {
	pi, err := c.ProtocolInfo(ctx)
	if err != nil {
		return err
	}
	has := map[string]bool{}
	for _, m := range pi.Methods {
		has[m] = true
	}
	switch {
	case has["NULL"]:
		return c.ok(ctx, "AUTHENTICATE")
	case has["SAFECOOKIE"]:
		if cookiePath == "" || cookiePath == "auto" {
			cookiePath = pi.CookieFile
		}
		if cookiePath == "" {
			return errors.New("tor control: SAFECOOKIE without a cookie file")
		}
		cookie, err := readCookie(cookiePath)
		if err != nil {
			return err
		}
		defer wipe(cookie)
		return c.safeCookie(ctx, cookie)
	default:
		return ErrNoUsableAuth
	}
}

func (c *Conn) safeCookie(ctx context.Context, cookie []byte) error {
	cn := make([]byte, nonceLen)
	if _, err := rand.Read(cn); err != nil {
		return err
	}
	rep, err := c.Command(ctx, "AUTHCHALLENGE SAFECOOKIE "+hex.EncodeToString(cn))
	if err != nil {
		return err
	}
	if err := rep.Err(); err != nil {
		return err
	}
	text, ok := strings.CutPrefix(rep.Lines[0].Text, "AUTHCHALLENGE ")
	if !ok {
		return errors.New("tor control: bad AUTHCHALLENGE reply")
	}
	kv := parseKV(text)
	sh, err1 := hex.DecodeString(kv["SERVERHASH"])
	sn, err2 := hex.DecodeString(kv["SERVERNONCE"])
	if err1 != nil || err2 != nil || len(sh) != sha256.Size || len(sn) != nonceLen {
		return errors.New("tor control: bad AUTHCHALLENGE reply")
	}
	msg := make([]byte, 0, len(cookie)+len(cn)+len(sn))
	msg = append(append(append(msg, cookie...), cn...), sn...)
	defer wipe(msg)
	if !hmac.Equal(sh, mac(serverKey, msg)) {
		return ErrServerHash
	}
	return c.ok(ctx, "AUTHENTICATE "+hex.EncodeToString(mac(clientKey, msg)))
}

func (c *Conn) ok(ctx context.Context, cmd string) error {
	rep, err := c.Command(ctx, cmd)
	if err != nil {
		return err
	}
	return rep.Err()
}

func mac(key string, msg []byte) []byte {
	h := hmac.New(sha256.New, []byte(key))
	h.Write(msg)
	return h.Sum(nil)
}

// readCookie reads the 32-byte cookie into locked memory. A file of any other size is refused.
func readCookie(path string) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- profile or PROTOCOLINFO path; see Authenticate
	if err != nil {
		return nil, fmt.Errorf("tor control: cookie: %w", err)
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, cookieLen+1)
	_ = unix.Mlock(buf) // best effort (§19.3)
	n, err := io.ReadFull(f, buf)
	if n != cookieLen || !errors.Is(err, io.ErrUnexpectedEOF) {
		wipe(buf)
		return nil, errors.New("tor control: cookie file is not 32 bytes")
	}
	return buf[:cookieLen], nil
}

func wipe(b []byte) {
	b = b[:cap(b)]
	for i := range b {
		b[i] = 0
	}
	_ = unix.Munlock(b)
}

// parseKV parses space-separated KEY=VALUE pairs; values may be quoted strings (C escapes).
func parseKV(s string) map[string]string {
	out := map[string]string{}
	for s = strings.TrimLeft(s, " "); s != ""; s = strings.TrimLeft(s, " ") {
		key, rest, ok := strings.Cut(s, "=")
		if !ok || strings.Contains(key, " ") {
			_, s, _ = strings.Cut(s, " ")
			continue
		}
		var val string
		if strings.HasPrefix(rest, `"`) {
			val, s = unquote(rest)
		} else {
			val, s, _ = strings.Cut(rest, " ")
		}
		out[key] = val
	}
	return out
}

// unquote reads a QuotedString at the start of s and returns it and the remainder.
func unquote(s string) (string, string) {
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '"':
			return b.String(), s[i+1:]
		case '\\':
			if i+1 < len(s) {
				i++
				switch s[i] {
				case 'n':
					b.WriteByte('\n')
				case 't':
					b.WriteByte('\t')
				case 'r':
					b.WriteByte('\r')
				default:
					b.WriteByte(s[i])
				}
			}
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String(), ""
}
