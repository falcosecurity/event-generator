package helper

import (
	"os/exec"

	"github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(RunShell)

// RunShell executes a dummy command in a shell.
func RunShell(h events.Helper) error {
	return exec.Command("bash", "-c", "ls > /dev/null").Run()
}
