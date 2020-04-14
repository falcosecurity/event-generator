package syscall

import (
	"github.com/falcosecurity/event-generator/events"
	_ "github.com/falcosecurity/event-generator/events/helper"
)

var _ = events.Register(RunShellUntrusted)

func RunShellUntrusted(h events.Helper) error {
	return h.SpawnAs("httpd", "helper.RunShell")
}
