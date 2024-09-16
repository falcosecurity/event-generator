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
	ModifyContainerEntrypoint,
	events.WithDisabled(), // this rules is not included in falco_rules.yaml (stable rules), so disable the action
)

func ModifyContainerEntrypoint(h events.Helper) error {
	if !h.InContainer() {
		return &events.ErrSkipped{
			Reason: "only applicable to containers",
		}
	}

	// it is enough to open /proc/self/exe or a file under /proc/self/fd/ for writing to trigger the rule
	file, err := os.OpenFile("/proc/self/fd/1", os.O_WRONLY, os.FileMode(0644))
	if err != nil {
		// skip permission denied errors
		if errors.Is(err, os.ErrPermission) {
			return &events.ErrSkipped{
				Reason: "permission denied while trying to open /proc/self/fd/1 for writing",
			}
		}
		return err
	}
	defer func() {
		if err := file.Close(); err != nil {
			h.Log().WithError(err).Error("failed to close /proc/self/fd/1 file")
		}
	}()

	return nil
}
