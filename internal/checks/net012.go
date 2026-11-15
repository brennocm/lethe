package checks

import "lethe/internal/contracts"

// NET012 is STUN/WebRTC outside the tunnel, classified by the capture sensor (§8.3).
type NET012 struct{}

func (NET012) ID() string { return "NET-012" }

var net012Meta = meta{kind: Passive, sev: contracts.SeverityCritical, sources: []SourceID{SrcCapture}, st: []string{"ST-NET-012"}}

func (NET012) Kind() Kind                          { return net012Meta.Kind() }
func (NET012) DefaultSeverity() contracts.Severity { return net012Meta.DefaultSeverity() }
func (NET012) Sources() []SourceID                 { return net012Meta.Sources() }
func (NET012) SelfTestCases() []string             { return net012Meta.SelfTestCases() }
