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
	"os"
	"path/filepath"

	"github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(
	DeleteOrRenameShellHistory,
	events.WithDisabled(), // this rule is not included in falco_rules.yaml (stable rules), so disable the action
)

func DeleteOrRenameShellHistory(h events.Helper) error {
	// create a unique temp directory
	tmpDir, err := os.MkdirTemp("", "falco-event-generator-syscall-DeleteOrRenameShellHistory-")
	if err != nil {
		return err
	}
	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			h.Log().WithError(err).Error("failed to remove temp directory")
		}
	}()

	history := filepath.Join(tmpDir, "ash_history")

	// create the file
	if err := os.WriteFile(history, nil, os.FileMode(0600)); err != nil {
		return err
	}
	defer func() {
		if err := os.Remove(history); err != nil {
			h.Log().WithError(err).Error("failed to remove temp file")
		}
	}()

	return nil
}
