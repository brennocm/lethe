package gui

import (
	"context"
	"os"
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
	u.svcRunning = true
	u.svcBtn.Hide()
	u.svcStatus.SetText(u.t("service_btn_password"))
	u.svcBusy.Show()
	u.svcBar.Start()
	u.setFlash(u.t("service_starting"))
	u.wg.Add(1)
	go func() {
		defer u.wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute) // the password prompt waits for the operator
		defer cancel()
		// lethed@ makes ~/lethe writable only if it exists when the service starts
		// (ReadWritePaths=-/home/%i/lethe): create it first, or a first use done after the start
		// would leave the session directory read-only until a restart
		if u.opt.Home != "" {
			_ = os.MkdirAll(u.firstDir(), 0o700)
		}
		err := u.opt.StartService(ctx)
		if err != nil {
			fyne.Do(u.resetStart)
			u.say(u.t("service_btn"), err, "")
			return
		}
		fyne.Do(func() {
			u.svcWait = u.opt.Now().Add(startWait)
			u.svcStatus.SetText(u.t("service_btn_waiting"))
			u.setFlash(u.t("service_started"))
		})
		u.poll()
	}()
}

// startWait is how long the panel waits, after systemd started the unit, for the daemon to
// answer before it says the start failed (the unit restarts a daemon that dies, so systemd's
// answer alone does not mean lethe is up).
const startWait = 15 * time.Second

// followStart ends the wait after a start: the daemon answered, or it did not within startWait
// and the panel says where the reason is. Called by Apply on every poll.
func (u *UI) followStart() {
	if u.svcWait.IsZero() {
		return
	}
	switch {
	case u.offline == nil:
		u.resetStart()
		u.setFlash("")
	case u.opt.Now().After(u.svcWait):
		u.resetStart()
		u.setFlash(u.t("service_no_answer"))
	}
}

// resetStart puts the start button back as it was.
func (u *UI) resetStart() {
	u.svcWait = time.Time{}
	u.svcRunning = false
	u.svcBar.Stop()
	u.svcBusy.Hide()
	show(u.svcBtn, u.offline != nil && u.opt.StartService != nil)
	u.relayout()
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
