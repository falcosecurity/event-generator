// +build linux

package syscall

import (
	"golang.org/x/sys/unix"

	"github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(
	ChangeThreadNamespace,
	events.WithDisabled(), // the rule is not enabled by default, so disable the action too
)

func ChangeThreadNamespace(h events.Helper) error {
	// It doesn't matter that the arguments to Setns are
	// bogus. It's the attempt to call it that will trigger the
	// rule.
	h.Log().Debug("does not result in a falco notification in containers, unless container run with --privileged or --security-opt seccomp=unconfined")
	unix.Setns(0, 0)
	return nil
}
