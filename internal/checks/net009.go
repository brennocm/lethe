package checks

import "lethe/internal/contracts"

// NET009 is LAN broadcast with identifiers (mDNS, LLMNR, NetBIOS, SSDP), classified by the
// capture sensor (§8.3). Hostname decoding and the baseline comparison (C on match) come in M9.
type NET009 struct{}

func (NET009) ID() string { return "NET-009" }

var net009Meta = meta{kind: Passive, sev: contracts.SeverityWarning, sources: []SourceID{SrcCapture}}

func (NET009) Kind() Kind                          { return net009Meta.Kind() }
func (NET009) DefaultSeverity() contracts.Severity { return net009Meta.DefaultSeverity() }
func (NET009) Sources() []SourceID                 { return net009Meta.Sources() }
func (NET009) SelfTestCases() []string             { return net009Meta.SelfTestCases() }
