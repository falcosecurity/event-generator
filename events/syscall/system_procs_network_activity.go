package syscall

import (
	"github.com/falcosecurity/event-generator/events"
	_ "github.com/falcosecurity/event-generator/events/helper"
)

var _ = events.Register(SystemProcsNetworkActivity)

func SystemProcsNetworkActivity(h events.Helper) error {
	return h.SpawnAs("sha1sum", "helper.NetworkActivity")
}
