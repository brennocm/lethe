package gui

import (
	"context"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/dialog"

	"lethe/internal/contracts"
)

// Run polls the daemon once a second (status and heartbeat) and follows its event stream until
// ctx ends. A daemon that does not answer turns the panel offline: the verdict says lethe is not
// running and, with a way to start the service, the panel offers it.
func (u *UI) Run(ctx context.Context) {
	if evs, err := u.be.Recent(maxEvents); err == nil {
		fyne.Do(func() { u.Apply(u.st, evs) })
	}
	go u.stream(ctx)
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		u.poll()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// poll asks the status once and applies it.
func (u *UI) poll() {
	_ = u.be.Heartbeat()
	st, err := u.be.Status()
	fyne.Do(func() {
		u.offline = err
		if err != nil {
			st = contracts.Status{}
		}
		u.Apply(st, nil)
	})
}

func (u *UI) stream(ctx context.Context) {
	for ctx.Err() == nil {
		ch, err := u.be.Subscribe(ctx)
		if err == nil {
			for ev := range ch {
				fyne.Do(func() { u.Apply(u.st, []contracts.Event{ev}) })
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

// startService asks systemd to start lethe for this operator (polkit asks an administrator's
// password); the next poll finds the daemon.
func (u *UI) startService() {
	u.svcBtn.Disable()
	u.setFlash(u.t("service_starting"))
	u.wg.Add(1)
	go func() {
		defer u.wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute) // the password prompt waits for the operator
		defer cancel()
		err := u.opt.StartService(ctx)
		fyne.Do(u.svcBtn.Enable)
		u.say(u.t("service_btn"), err, u.t("service_started"))
		if err == nil {
			u.poll()
		}
	}()
}

// askCleanup confirms, then releases a block no session owns: lethe cleanup removes only the
// lethe* tables, as root, after polkit's password. The block was left on purpose (a crash must
// not leak), so the operator decides, knowing nothing watches the network afterwards.
func (u *UI) askCleanup() {
	dialog.NewCustomConfirm(u.t("cleanup_btn"), u.t("cleanup_btn"), u.t("cancel"), wrapped(u.t("cleanup_ask")), func(ok bool) {
		if !ok {
			return
		}
		u.cleanBtn.Disable()
		u.cleanOff.Disable()
		u.setFlash(u.t("service_starting"))
		u.wg.Add(1)
		go func() {
			defer u.wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			err := u.opt.Cleanup(ctx)
			fyne.Do(func() { u.cleanBtn.Enable(); u.cleanOff.Enable() })
			u.say(u.t("cleanup_btn"), err, u.t("cleanup_done"))
			if err == nil && u.offline == nil {
				u.poll()
			}
		}()
	}, u.panel).Show()
}
