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

	"github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(DropAndExecuteNewBinaryInContainer)

func DropAndExecuteNewBinaryInContainer(h events.Helper) error {
	if !h.InContainer() {
		return &events.ErrSkipped{
			Reason: "only applicable to containers",
		}
	}

	// find the path of the ls binary
	ls, err := exec.LookPath("ls")
	if err != nil {
		return &events.ErrSkipped{
			Reason: "ls executable file not found in $PATH",
		}
	}

	// read the ls binary content
	lsContent, err := os.ReadFile(ls)
	if err != nil {
		return err
	}

	// ensure /bin exists
	if _, err := os.Stat("/bin"); os.IsNotExist(err) {
		if err := os.Mkdir("/bin", os.FileMode(0755)); err != nil {
			return err
		}
		// remove /bin directory
		defer func() {
			if err := os.RemoveAll("/bin"); err != nil {
				h.Log().WithError(err).Error("failed to remove /bin directory")
			}
		}()
	}

	// generate new "random" binary name
	file := filepath.Join("/bin", fmt.Sprintf("falco-event-generator-syscall-DropAndExecuteNewBinaryInContainer-%s", randomString(6)))

	// create file and set execute permission
	if err = os.WriteFile(file, lsContent, os.FileMode(0755)); err != nil {
		return err
	}
	defer func() {
		if err := os.Remove(file); err != nil {
			h.Log().WithError(err).Error("failed to remove temp file")
		}
	}()

	// note: executing the following command might fail, but enough to trigger the rule, so we ignore any error
	if err := exec.Command(file).Run(); err != nil {
		h.Log().WithError(err).Debug("failed to run ls command (might be ok)")
	}

	return nil
}
