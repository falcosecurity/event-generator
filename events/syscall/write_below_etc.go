package syscall

import (
	"io/ioutil"
	"os"

	"github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(WriteBelowEtc)

func WriteBelowEtc(h events.Helper) error {
	const filename = "/etc/created-by-event-generator"
	h.Log().Infof("writing to %s", filename)
	defer os.Remove(filename)
	return ioutil.WriteFile(filename, nil, os.FileMode(0755))
}
