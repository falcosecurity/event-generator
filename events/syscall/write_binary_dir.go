package syscall

import (
	"io/ioutil"
	"os"

	"github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(WriteBinaryDir)

func WriteBinaryDir(h events.Helper) error {
	h.Log().Info("Writing to /bin/created-by-event-generator-sh...")
	return ioutil.WriteFile("/bin/created-by-event-generator-sh", nil, os.ModePerm)
}
