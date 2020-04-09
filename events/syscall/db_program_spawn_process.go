package syscall

import (
	"github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(DbProgramSpawnProcess)

func DbProgramSpawnProcess(h events.Helper) error {
	return h.SpawnAs("mysqld", "syscall.ExecLs")
}
