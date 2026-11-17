package checks

import (
	"lethe/internal/contracts"
)

// HOST006 is "disk and swap without encryption" (spec §9.4).
type HOST006 struct{}

func (HOST006) ID() string { return "HOST-006" }

var host006Meta = meta{kind: Preflight, sev: contracts.SeverityWarning, sources: []SourceID{SrcHostinfo}}

func (HOST006) Kind() Kind                          { return host006Meta.Kind() }
func (HOST006) DefaultSeverity() contracts.Severity { return host006Meta.DefaultSeverity() }
func (HOST006) Sources() []SourceID                 { return host006Meta.Sources() }
func (HOST006) SelfTestCases() []string             { return host006Meta.SelfTestCases() }

// Evaluate: WARNING when / is not on dm-crypt or a swap device is neither encrypted nor zram.
// An unknown root (no sysfs, btrfs subvolume…) is not reported.
func (HOST006) Evaluate(rootEncrypted *bool, plainSwap []string) []Finding {
	plainRoot := rootEncrypted != nil && !*rootEncrypted
	if !plainRoot && len(plainSwap) == 0 {
		return nil
	}
	return []Finding{{Check: "HOST-006", Severity: contracts.SeverityWarning, Data: map[string]any{
		"root_plain": plainRoot, "plain_swap": len(plainSwap),
	}}}
}
