package syscall

import (
	"os"

	"github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(MkdirBinaryDirs)

func MkdirBinaryDirs(h events.Helper) error {
	const dirname = "/bin/directory-created-by-event-generator"
	h.Log().Infof("writing to %s", dirname)
	defer os.Remove(dirname)
	return os.Mkdir(dirname, os.FileMode(0755))
}
