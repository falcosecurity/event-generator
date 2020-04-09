package runner

import (
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"

	logger "github.com/sirupsen/logrus"
	"k8s.io/cli-runtime/pkg/resource"
)

type helper struct {
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

// Cleanup registers a function to be called when the action complete or later.
// Cleanup functions registered from within the same action will be called in last added,
// first called order.
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
