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

var _ = events.Register(ClearLogActivities)

func ClearLogActivities(h events.Helper) error {
	// create a unique temp directory
	tmpDir, err := os.MkdirTemp("", "falco-event-generator-syscall-ClearLogActivities-")
	if err != nil {
		return err
	}
	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			h.Log().WithError(err).Error("failed to remove temp directory")
		}
	}()

	filename := filepath.Join(tmpDir, "syslog")

	// open or create the file with write-only access and truncate its contents if it exists
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(0644))
	if err != nil {
		return err
	}
	defer func() {
		if err := file.Close(); err != nil {
			h.Log().WithError(err).Error("failed to close temp file")
		}
	}()

	return nil
}
