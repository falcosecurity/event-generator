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
	"os/exec"

	"github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(
	LaunchRemoteFileCopyToolsInContainer,
	events.WithDisabled(), // this rules is not included in falco_rules.yaml (stable rules), so disable the action
)

func LaunchRemoteFileCopyToolsInContainer(h events.Helper) error {
	if h.InContainer() {
		// Launch a remote file copy tool (e.g., scp) within the container
		cmd := exec.Command("scp")

		h.Log().Info("Remote file copy tool launched in container")
		err := cmd.Run()
		if err != nil {
			h.Log().WithError(err).Error("Failed to launch remote file copy tool")
			return err
		}
	}
	return &events.ErrSkipped{
		Reason: "'Launch Remote File Copy Tools In Container' is applicable only to containers.",
	}
}
