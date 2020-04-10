package runner

import (
	"errors"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/falcosecurity/event-generator/events"
	logger "github.com/sirupsen/logrus"
	"k8s.io/cli-runtime/pkg/resource"
)

var _ events.Helper = &helper{}

// Helper errors
var (
	ErrSelfSpawnAs = errors.New("cannot spawn the same action")
)

type helper struct {
	name    string
	runner  *Runner
	log     *logger.Entry
	builder *resource.Builder
	cleanup func()
}

func (h *helper) Log() *logger.Entry {
	return h.log
}

func (h *helper) ResourceBuilder() *resource.Builder {
	// todo(leogr): handle nil case
	return h.builder
}

func (h *helper) Cleanup(f func(), args ...interface{}) {
	oldCleanup := h.cleanup
	h.cleanup = func() {
		if oldCleanup != nil {
			defer oldCleanup()
		}
		args = append([]interface{}{"clenaup "}, args...)
		h.Log().Info(args...)
		f()
	}
}

func (h *helper) SpawnAs(name string, action string) error {
	h.Log().WithField("arg", action).Infof(`spawn as "%s"`, name)
	if name == h.name {
		return ErrSelfSpawnAs
	}
	tmpDir, err := ioutil.TempDir(os.TempDir(), "falco-event-generator")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	name = filepath.Join(tmpDir, name)
	if err := os.Symlink(h.runner.exePath, name); err != nil {
		return err
	}

	cmd := exec.Command(name, append(h.runner.exeArgs, action)...)

	out := h.runner.log.Out
	cmd.Stdout = out
	cmd.Stderr = out
	if err := cmd.Run(); err != nil {
		return err
	}

	return nil
}
