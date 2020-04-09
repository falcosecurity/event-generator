package syscall

import (
	"os"

	"github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(ReadSensitiveFile)

func ReadSensitiveFile(h events.Helper) error {
	const filename = "/etc/shadow"
	file, err := os.Open(filename)
	defer file.Close()
	return err
}
