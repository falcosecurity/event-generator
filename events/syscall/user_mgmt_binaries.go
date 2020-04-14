// +build linux

package syscall

import (
	"github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(UserMgmtBinaries)

func UserMgmtBinaries(h events.Helper) error {
	h.Log().Debug("does not result in a falco notification in containers")
	return h.SpawnAs("vipw", "helper.ExecLs")
}
