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
	"context"
	"os/exec"
	"time"

	"github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(DisallowedSSHConnectionNonStandardPort)

func DisallowedSSHConnectionNonStandardPort(h events.Helper) error {
	ssh, err := exec.LookPath("ssh")
	if err != nil {
		// if we don't have a SSH, just bail
		return &events.ErrSkipped{
			Reason: "ssh executable file not found in $PATH",
		}
	}

	// note: executing the following command might fail, but enough to trigger the rule, so we ignore any error
	if err := runCmd(context.Background(), 1*time.Second, ssh, "user@example.com", "-p", "443"); err != nil {
		h.Log().WithError(err).Debug("failed to run ssh command (this is expected)")
	}

	return nil
}
