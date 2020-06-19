// +build linux

package syscall

import (
	"github.com/falcosecurity/event-generator/events"

	"os/exec"
)

var _ = events.Register(
	ScheduleCronJobs,
	events.WithDisabled(), // the rule is not enabled by default, so disable the action too
)

func ScheduleCronJobs(h events.Helper) error {
	// This just lists crons, but sufficies to trigger the event
	// Cron detection is not enabled by default, see `consider_all_cron_jobs` in rules.yaml

	path, err := exec.LookPath("crontab")
	if err != nil {
		// if we don't have a crontab, just bail
		return &events.ErrSkipped{
			Reason: "crontab utility not found in path",
		}
	}
	cmd := exec.Command(path, "-l")
	err = cmd.Run()

	// silently ignore crontab exit status 1
	if exitErr, isExitErr := err.(*exec.ExitError); isExitErr {
		h.Log().WithError(exitErr).Debug("silently ignore exit status")
		return nil
	}
	return err
}
