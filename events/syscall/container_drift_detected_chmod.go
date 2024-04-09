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

	"github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(
	ContainerDriftDetcted,
	events.WithDisabled(), // this rules is not included in falco_rules.yaml (stable rules), so disable the action
)

func ContainerDriftDetcted(h events.Helper) error {
	if h.InContainer() {
		filename := "/created-by-event-generator"
		if err := os.WriteFile(filename, nil, 0755); err != nil {
			h.Log().WithError(err).Error("Error creating an empty file")
			return err
		}
		defer os.Remove(filename) // Remove file after function return

		// Set execute permission on script file to make it executable
		if err := os.Chmod(filename, 0755); err != nil {
			h.Log().WithError(err).Error("Error setting execute permission on script file")
			return err
		}
	}
	return &events.ErrSkipped{
		Reason: "'Container Drift Detected (chmod)' is applicable only to containers.",
	}
}
