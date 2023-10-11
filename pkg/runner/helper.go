// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package runner

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/falcosecurity/event-generator/events"
	logger "github.com/sirupsen/logrus"
	"k8s.io/cli-runtime/pkg/resource"
)

var _ events.Helper = &helper{}

// Helper errors
var (
	ErrChildSpawn = errors.New("cannot re-spawn a child process")
)

type helper struct {
	action  string
	runner  *Runner
	log     *logger.Entry
	hasLog  bool
	builder *resource.Builder
	cleanup func()
}

func (h *helper) Log() *logger.Entry {
	h.hasLog = true
	return h.log
}

func (h *helper) Sleep(d time.Duration) {
	h.log.Infof("sleep for %s", d) // do not set hasLog
	time.Sleep(d)
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
		log := h.Log()
		if len(args) > 0 {
			if l, ok := args[0].(*logger.Entry); ok {
				log = l
				args = args[1:]
			}
		}
		args = append([]interface{}{"cleanup "}, args...)
		log.Info(args...)
		f()
	}
}

func (h *helper) SpawnAs(name string, action string, args ...string) error {
	fullArgs := append([]string{fmt.Sprintf("^%s$", action)}, args...)
	h.Log().WithField("args", strings.Join(fullArgs, " ")).Infof(`spawn as "%s"`, name)
	if h.Spawned() {
		return ErrChildSpawn
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

	cmd := exec.Command(name, append(h.runner.exeArgs, fullArgs...)...)

	out := h.runner.log.Out
	cmd.Stdout = out
	cmd.Stderr = out
	if err := cmd.Run(); err != nil {
		return err
	}

	return nil
}

func (h *helper) Spawned() bool {
	return h.runner.alias != ""
}

func (h *helper) InContainer() bool {
	return h.runner.inCnt
}
