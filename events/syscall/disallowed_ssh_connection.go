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
	"github.com/falcosecurity/event-generator/events"
	"os/exec"
)

var _ = events.Register(
	DisallowedSSHConnection,
	events.WithDisabled(), // this rule is not included in falco_rules.yaml (stable rules), so disable the action
)

func DisallowedSSHConnection(h events.Helper) error {
	path, err := exec.LookPath("ssh")
	if err != nil {
		// If we don't have an SSH, just bail
		return &events.ErrSkipped{
			Reason: "ssh utility not found in path",
		}
	}
	cmd := exec.Command("timeout", "1s", path, "user@example.com", "-p", "22")
	err = cmd.Run()
	if err != nil {
		return err
	}
	return nil
}
