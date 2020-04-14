// +build linux

package syscall

import (
	"os/exec"

	"github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(SystemUserInteractive)

func SystemUserInteractive(h events.Helper) error {
	err := runAsUser(h, "daemon", "/bin/login")

	// silently ignore /bin/login exit status 1
	if exitErr, isExitErr := err.(*exec.ExitError); isExitErr {
		h.Log().WithError(exitErr).Debug("silently ignore exit status")
		return nil
	}
	return err
}
