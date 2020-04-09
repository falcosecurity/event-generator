package syscall

import (
	"os"

	"github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(ModifyBinaryDirs)

func ModifyBinaryDirs(h events.Helper) error {
	const from = "/bin/true"
	const to = "/bin/true.event-generator"
	h.Log().Infof("modifying %s to %s and back", from, to)
	if err := os.Rename(from, to); err != nil {
		return err
	}
	return os.Rename(to, from)
}
