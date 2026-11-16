// Package baseline holds the operator's real identity (spec §12). Values live in clear only
// inside the age-encrypted file and in memory; they must never reach events, logs, reports or IPC.
package baseline

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	"filippo.io/age"
)

// DefaultWorkFactor is the scrypt work factor used for the passphrase (age default, ~1 s).
const DefaultWorkFactor = 18

const maxBaselineSize = 1 << 20

// Baseline is the decrypted content of baseline.age.
type Baseline struct {
	Version     int       `json:"version"`
	CreatedAt   time.Time `json:"created_at"`
	ToolVersion string    `json:"tool_version"`
	Networks    []Network `json:"networks"`
	PermMACs    []string  `json:"perm_macs"`
	Hostname    string    `json:"hostname"`
	Username    string    `json:"username"`
	Timezone    string    `json:"timezone"`
	Locale      string    `json:"locale"`
	Keyboard    string    `json:"keyboard"`
	LogIdentity string    `json:"log_identity"`
}

// Network is one known network (home, office...).
type Network struct {
	Name       string   `json:"name"`
	PublicIPv4 string   `json:"public_ipv4,omitempty"`
	PublicIPv6 string   `json:"public_ipv6,omitempty"`
	ASN        uint32   `json:"asn,omitempty"`
	Provider   string   `json:"provider,omitempty"`
	Resolvers  []string `json:"resolvers,omitempty"`
	GatewayIP  string   `json:"gateway_ip,omitempty"`
	GatewayMAC string   `json:"gateway_mac,omitempty"`
	SSIDs      []string `json:"ssids,omitempty"`
}

// New creates an empty baseline with a fresh log identity.
func New(now time.Time, toolVersion string) (*Baseline, error) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, err
	}
	return &Baseline{Version: 1, CreatedAt: now.UTC(), ToolVersion: toolVersion, LogIdentity: id.String()}, nil
}

// LogIdentity parses the embedded age identity that opens session logs.
func (b *Baseline) Identity() (*age.X25519Identity, error) {
	return age.ParseX25519Identity(b.LogIdentity)
}

// Validate checks field formats.
func (b *Baseline) Validate() error {
	var errs []error
	if b.Version != 1 {
		errs = append(errs, fmt.Errorf("unsupported baseline version %d", b.Version))
	}
	if _, err := b.Identity(); err != nil {
		errs = append(errs, fmt.Errorf("log_identity: %w", err))
	}
	for _, m := range b.PermMACs {
		if _, err := net.ParseMAC(m); err != nil {
			errs = append(errs, fmt.Errorf("perm_macs: %q: %w", m, err))
		}
	}
	names := map[string]bool{}
	for i, n := range b.Networks {
		errs = append(errs, n.validate(i))
		if names[n.Name] {
			errs = append(errs, fmt.Errorf("networks[%d]: duplicate name %q", i, n.Name))
		}
		names[n.Name] = true
	}
	return errors.Join(errs...)
}

func (n Network) validate(i int) error {
	var errs []error
	bad := func(field, v string, err error) {
		errs = append(errs, fmt.Errorf("networks[%d].%s: %q: %w", i, field, v, err))
	}
	if strings.TrimSpace(n.Name) == "" {
		errs = append(errs, fmt.Errorf("networks[%d].name is required", i))
	}
	if n.PublicIPv4 != "" {
		if a, err := netip.ParseAddr(n.PublicIPv4); err != nil || !a.Is4() {
			bad("public_ipv4", n.PublicIPv4, errors.New("not an IPv4 address"))
		}
	}
	if n.PublicIPv6 != "" {
		if a, err := netip.ParseAddr(n.PublicIPv6); err != nil || !a.Is6() {
			bad("public_ipv6", n.PublicIPv6, errors.New("not an IPv6 address"))
		}
	}
	for _, r := range n.Resolvers {
		if _, err := netip.ParseAddr(r); err != nil {
			bad("resolvers", r, err)
		}
	}
	if n.GatewayIP != "" {
		if _, err := netip.ParseAddr(n.GatewayIP); err != nil {
			bad("gateway_ip", n.GatewayIP, err)
		}
	}
	if n.GatewayMAC != "" {
		if _, err := net.ParseMAC(n.GatewayMAC); err != nil {
			bad("gateway_mac", n.GatewayMAC, err)
		}
	}
	return errors.Join(errs...)
}

// AddNetwork appends a validated network.
func (b *Baseline) AddNetwork(n Network) error {
	b.Networks = append(b.Networks, n)
	if err := b.Validate(); err != nil {
		b.Networks = b.Networks[:len(b.Networks)-1]
		return err
	}
	return nil
}

// Values lists every identifying value, for redaction and leak tests. It excludes the log identity.
func (b *Baseline) Values() []string {
	var out []string
	add := func(vs ...string) {
		for _, v := range vs {
			if strings.TrimSpace(v) != "" {
				out = append(out, v)
			}
		}
	}
	add(b.PermMACs...)
	add(b.Hostname, b.Username)
	for _, n := range b.Networks {
		add(n.PublicIPv4, n.PublicIPv6, n.Provider, n.GatewayIP, n.GatewayMAC)
		add(n.Resolvers...)
		add(n.SSIDs...)
	}
	return out
}

// Redact replaces every baseline value in s with "[baseline]" (defense in depth for messages).
func (b *Baseline) Redact(s string) string {
	matched := map[string]bool{}
	for _, f := range b.fields() {
		if len(f.value) >= 3 {
			f.exact = false
			s = replaceFold(s, f, matched)
		}
	}
	return s
}

// Encrypt serializes and encrypts the baseline with a passphrase (age scrypt).
func Encrypt(b *Baseline, passphrase []byte, workFactor int) ([]byte, error) {
	if len(passphrase) < 8 {
		return nil, errors.New("passphrase must have at least 8 characters")
	}
	r, err := age.NewScryptRecipient(string(passphrase))
	if err != nil {
		return nil, err
	}
	if workFactor > 0 {
		r.SetWorkFactor(workFactor)
	}
	return encrypt(b, r)
}

// EncryptRecovery encrypts the baseline to institutional X25519 recipients (separate file).
// age forbids mixing a passphrase with other recipients in one file.
func EncryptRecovery(b *Baseline, recipients []age.Recipient) ([]byte, error) {
	if len(recipients) == 0 {
		return nil, errors.New("no recovery recipients")
	}
	return encrypt(b, recipients...)
}

func encrypt(b *Baseline, recipients ...age.Recipient) ([]byte, error) {
	if err := b.Validate(); err != nil {
		return nil, err
	}
	plain, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	defer wipe(plain)
	var out bytes.Buffer
	w, err := age.Encrypt(&out, recipients...)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plain); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// ErrWrongPassphrase is returned when the passphrase does not open the baseline.
var ErrWrongPassphrase = errors.New("wrong passphrase (or not a baseline file)")

// Decrypt opens a passphrase-encrypted baseline.
func Decrypt(data, passphrase []byte) (*Baseline, error) {
	id, err := age.NewScryptIdentity(string(passphrase))
	if err != nil {
		return nil, err
	}
	return DecryptWith(data, id)
}

// DecryptWith opens a baseline with any age identity (recovery path).
func DecryptWith(data []byte, ids ...age.Identity) (*Baseline, error) {
	r, err := age.Decrypt(bytes.NewReader(data), ids...)
	if err != nil {
		return nil, ErrWrongPassphrase
	}
	plain, err := io.ReadAll(io.LimitReader(r, maxBaselineSize+1))
	if err != nil {
		return nil, fmt.Errorf("decrypt baseline: %w", err)
	}
	defer wipe(plain)
	if len(plain) > maxBaselineSize {
		return nil, errors.New("baseline too large")
	}
	var b Baseline
	dec := json.NewDecoder(bytes.NewReader(plain))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return nil, fmt.Errorf("baseline content: %w", err)
	}
	if err := b.Validate(); err != nil {
		return nil, err
	}
	return &b, nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
