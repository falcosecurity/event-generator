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

var _ = events.Register(FindAwsCredentials)

func FindAwsCredentials(h events.Helper) error {
	path, err := exec.LookPath("find")
	if err != nil {
		// if we don't have a find, just bail
		return &events.ErrSkipped{
			Reason: "find utility not found in path",
		}
	}
	cmd := exec.Command(path, ".aws/credentials")
	err = cmd.Run()

	// silently ignore find exit status 1
	if exitErr, isExitErr := err.(*exec.ExitError); isExitErr {
		h.Log().WithError(exitErr).Debug("silently ignore exit status")
		return nil
	}
	return err
}
