package checks

import "lethe/internal/contracts"

// DNS001 is DNS outside the tunnel (udp/tcp 53, DoT/DoQ 853), classified by the capture
// sensor (§8.3). The qname travels only in Finding.Sensitive.
type DNS001 struct{}

func (DNS001) ID() string { return "DNS-001" }

var dns001Meta = meta{kind: Passive, sev: contracts.SeverityCritical, sources: []SourceID{SrcCapture}, st: []string{"ST-DNS-001"}}

func (DNS001) Kind() Kind                          { return dns001Meta.Kind() }
func (DNS001) DefaultSeverity() contracts.Severity { return dns001Meta.DefaultSeverity() }
func (DNS001) Sources() []SourceID                 { return dns001Meta.Sources() }
func (DNS001) SelfTestCases() []string             { return dns001Meta.SelfTestCases() }
