// +build linux

package syscall

import (
	"github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(UserMgmtBinaries)

func UserMgmtBinaries(h events.Helper) error {
	if h.InContainer() {
		return &events.ErrSkipped{
			Reason: "'User mgmt binaries' is excluded in containers",
		}
	}
	return h.SpawnAs("vipw", "helper.ExecLs")
}
