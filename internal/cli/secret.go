package cli

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"golang.org/x/term"
)

// borrowedFD reads a descriptor the caller owns. os.NewFile would take ownership and its
// finalizer would close the number later, possibly after it was reused by another file.
type borrowedFD int

func (fd borrowedFD) Read(b []byte) (int, error) {
	for {
		n, err := syscall.Read(int(fd), b)
		switch {
		case errors.Is(err, syscall.EINTR):
			continue
		case err != nil:
			return 0, err
		case n == 0 && len(b) > 0:
			return 0, io.EOF
		}
		return n, nil
	}
}

// passphraseSource reads passphrases from --passphrase-fd or the controlling terminal.
type passphraseSource struct {
	fd     int // -1 = terminal
	stderr io.Writer
	reader *bufio.Reader
}

func (p *passphraseSource) read(prompt string, confirm bool) ([]byte, error) {
	if p.fd >= 0 {
		if p.reader == nil {
			p.reader = bufio.NewReader(borrowedFD(p.fd))
		}
		line, err := p.reader.ReadBytes('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("read --passphrase-fd: %w", err)
		}
		pw := bytes.TrimRight(line, "\r\n")
		if len(pw) == 0 {
			return nil, errors.New("empty passphrase on --passphrase-fd")
		}
		return pw, nil
	}
	tty := int(os.Stdin.Fd()) // #nosec G115 -- fd fits in int
	if !term.IsTerminal(tty) {
		return nil, errors.New("no terminal to read the passphrase from; use --passphrase-fd N")
	}
	_, _ = fmt.Fprint(p.stderr, prompt)
	pw, err := term.ReadPassword(tty)
	_, _ = fmt.Fprintln(p.stderr)
	if err != nil {
		return nil, err
	}
	if confirm {
		_, _ = fmt.Fprint(p.stderr, "Repita a passphrase: ")
		again, err := term.ReadPassword(tty)
		_, _ = fmt.Fprintln(p.stderr)
		if err != nil {
			return nil, err
		}
		defer wipeBytes(again)
		if !bytes.Equal(pw, again) {
			wipeBytes(pw)
			return nil, errors.New("passphrases do not match")
		}
	}
	return pw, nil
}

func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// prompter asks line-based questions on the command's stdin.
type prompter struct {
	in  *bufio.Reader
	out io.Writer
}

func (p *prompter) ask(q string) (string, error) {
	_, _ = fmt.Fprint(p.out, q)
	line, err := p.in.ReadString('\n')
	if err != nil && (!errors.Is(err, io.EOF) || line == "") {
		if errors.Is(err, io.EOF) {
			return "", nil
		}
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if v := strings.TrimSpace(part); v != "" {
			out = append(out, v)
		}
	}
	return out
}
