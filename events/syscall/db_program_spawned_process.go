package syscall

import (
	"github.com/falcosecurity/event-generator/events"
	_ "github.com/falcosecurity/event-generator/events/helper"
)

var _ = events.Register(DbProgramSpawnedProcess)

func DbProgramSpawnedProcess(h events.Helper) error {
	return h.SpawnAs("mysqld", "helper.ExecLs")
}
