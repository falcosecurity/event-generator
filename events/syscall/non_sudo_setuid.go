// +build linux

package syscall

import (
	"github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(NonSudoSetuid)

func NonSudoSetuid(h events.Helper) error {
	if h.Spawned() {
		h.Log().Debug("first setuid to something non-root, then try to setuid back to root")
		if err := becameUser(h, "daemon"); err != nil {
			return err
		}
		err := becameUser(h, "root")
		h.Log().WithError(err).Debug("ignore root setuid error")
		return nil
	} else {
		return h.SpawnAs("child", "syscall.NonSudoSetuid")
	}
}
