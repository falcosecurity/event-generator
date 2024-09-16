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
	"errors"
	"os"

	"github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(
	MkdirBinaryDirs,
	events.WithDisabled(), // this rules is not included in falco_rules.yaml (stable rules), so disable the action
)

func MkdirBinaryDirs(h events.Helper) error {
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

	// create a unique temp directory under /bin
	tmpDir, err := os.MkdirTemp("/bin", "falco-event-generator-syscall-MkdirBinaryDirs-")
	if err != nil {
		// to trigger the rule, it is enough to try, so we ignore permission denied errors
		if errors.Is(err, os.ErrPermission) {
			return nil
		}
		return err
	}
	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			h.Log().WithError(err).Error("failed to remove temp directory")
		}
	}()

	return nil
}
