package syscall

import (
	"github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(ReadSensitiveFileTrustedAfterStartup)

func ReadSensitiveFileTrustedAfterStartup(h events.Helper) error {
	return h.SpawnAs("httpd", "syscall.ReadSensitiveFileUntrusted", "--sleep", "6s")
}
