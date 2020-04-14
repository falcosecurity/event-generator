package syscall

import (
	"github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(ReadSensitiveFileAfterStartup)

func ReadSensitiveFileAfterStartup(h events.Helper) error {
	return h.SpawnAs("httpd", "syscall.ReadSensitiveFile", "--sleep", "6s")
}
