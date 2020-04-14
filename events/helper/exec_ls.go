package helper

import (
	"os/exec"

	"github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(ExecLs)

func ExecLs(h events.Helper) error {
	return exec.Command("/bin/ls").Run()
}
