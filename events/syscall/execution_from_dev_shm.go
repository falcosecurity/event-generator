// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.
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

package syscall

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(ExecutionFromDevShm)

func ExecutionFromDevShm(h events.Helper) error {
	// ensure /dev exists
	if _, err := os.Stat("/dev"); os.IsNotExist(err) {
		if err := os.Mkdir("/dev", os.FileMode(0755)); err != nil {
			return err
		}
		// remove /dev directory
		defer func() {
			if err := os.RemoveAll("/dev"); err != nil {
				h.Log().WithError(err).Error("failed to remove /dev directory")
			}
		}()
	}

	// ensure /dev/shm exists
	if _, err := os.Stat("/dev/shm"); os.IsNotExist(err) {
		if err := os.Mkdir("/dev/shm", os.FileMode(0755)); err != nil {
			return err
		}
		// remove /dev/shm subdirectory only
		defer func() {
			if err := os.RemoveAll("/dev/shm"); err != nil {
				h.Log().WithError(err).Error("failed to remove /dev/shm directory")
			}
		}()
	}

	// generate new "random" file name under /dev/shm
	file := filepath.Join("/dev/shm", fmt.Sprintf("falco-event-generator-syscall-ExecutionFromDevShm-%s.sh", randomString(6)))

	// create executable script file
	if err := os.WriteFile(file, []byte("#!/bin/sh\n\necho 'hello world'\n"), os.FileMode(0755)); err != nil {
		return err
	}
	defer func() {
		if err := os.Remove(file); err != nil {
			h.Log().WithError(err).Error("failed to remove temp file")
		}
	}()

	// execute script file
	cmd := exec.Command("sh", "-c", file)
	if out, err := cmd.CombinedOutput(); err != nil {
		// to trigger the rule, it is enough to try, so we ignore permission denied errors
		if cmd.ProcessState.ExitCode() == 126 {
			return nil
		}
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}

	return nil
}
