package daemon

import (
	"fmt"
	"sort"
	"strings"

	"lethe/internal/contracts"
	"lethe/internal/engine"
)

// panicCause records why the session entered PANIC (for the lockdown explanation).
type panicCause struct {
	cause string // alert | operator | auth_failures
	alert string
	check string
}

// LeftoverLockdown describes lethe* tables found with no daemon running (spec §10.6 item 6).
func LeftoverLockdown(tables []string) *Lockdown {
	if len(tables) == 0 {
		return nil
	}
	return &Lockdown{
		What:   "a rede está bloqueada por tabelas do lethe que sobraram: " + strings.Join(tables, ", "),
		Why:    "nenhum daemon do lethe está rodando (ele caiu, foi morto com kill -9 ou a sessão foi interrompida); o bloqueio fica de propósito, para não vazar",
		Exit:   "sudo lethe cleanup (remove só as tabelas lethe*), ou reinicie a máquina",
		Tables: tables,
	}
}

// lockdownLocked describes the current block, or nil when lethe blocks nothing.
func (d *Daemon) lockdownLocked() *Lockdown {
	s := d.sess
	if s == nil {
		return nil
	}
	unacked := []string{}
	var tunnel []string
	for _, a := range d.eng.Alerts() {
		if a.Severity == contracts.SeverityCritical && !a.Acked {
			unacked = append(unacked, a.ID)
		}
		if a.State != engine.AlertResolved && (a.Check == "TUN-001" || a.Check == "TUN-003") {
			tunnel = append(tunnel, fmt.Sprintf("%s (%s)", a.ID, a.Check))
		}
	}
	sort.Strings(unacked)
	switch {
	case d.eng.Session() == engine.StatePanic:
		why := "pânico pedido pelo operador (lethe panic)"
		switch s.panic.cause {
		case "alert":
			why = fmt.Sprintf("o alerta %s (%s) acionou o pânico", s.panic.alert, s.panic.check)
			if s.panic.check == "SELF-006" {
				why += ": 5 passphrases erradas em 5 minutos"
			}
		case "auth_failures":
			why = "5 passphrases erradas em 5 minutos (SELF-006)"
		}
		exit := "lethe unpanic (pede a passphrase e confere túnel, rotas e IPv6 antes de liberar)"
		if len(unacked) > 0 {
			exit = fmt.Sprintf("reconheça os CRITICAL com lethe ack ID --reason \"...\" (%s) e depois rode lethe unpanic", strings.Join(unacked, ", "))
		}
		return &Lockdown{What: "a rede está bloqueada: pânico", Why: why,
			Exit: exit + "; se o túnel não voltar: lethe disarm encerra a sessão e libera a rede (pede a passphrase); se o lethe não responder: sudo lethe cleanup, ou reinicie a máquina"}
	case s.guardMode == engine.GuardStrict && s.confirming:
		return &Lockdown{What: "guarda estrito aplicado: só o túnel passa enquanto ele prova que funciona",
			Why:  fmt.Sprintf("o arm espera até %s por um handshake ou tráfego pelo túnel", s.prof.Guard.ArmWindow),
			Exit: "nada a fazer: sem a prova o lethe desfaz o bloqueio sozinho; abra uma página para acelerar"}
	case s.guardMode == engine.GuardStrict && len(tunnel) > 0:
		return &Lockdown{What: "a rede está bloqueada: guarda estrito sem túnel",
			Why:  "o túnel caiu (" + strings.Join(tunnel, ", ") + "); no estrito só o túnel passa, então nada sai pela rede física",
			Exit: "reconecte o túnel (a rede volta sozinha), ou lethe disarm para encerrar a sessão e liberar a rede"}
	}
	return nil
}
