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
	"os/exec"

	"github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(DropAndExecuteNewBinaryInContainer)

func DropAndExecuteNewBinaryInContainer(h events.Helper) error {
	if h.InContainer() {
		// Find the path of the ls binary
		lsPath, err := exec.LookPath("ls")
		if err != nil {
			return &events.ErrSkipped{
				Reason: "ls utility not found in path",
			}
		}

		// Read the ls binary content
		lsContent, err := os.ReadFile(lsPath)
		if err != nil {
			return err
		}

		// New binary which is duplicate of ls binary
		newBinaryPath := "/bin/ls-created-by-event-generator"

		err = os.WriteFile(newBinaryPath, lsContent, 0755)
		if err != nil {
			h.Log().WithError(err).Error("failed to create new file in /bin")
			return err
		}
		defer os.Remove(newBinaryPath) // CleanUp

		executeCmd := exec.Command(newBinaryPath)
		h.Log().Info("Executed a binary not part of base image")
		executeCmd.Run() // Rule triggers even the command is not successful
	}
	return &events.ErrSkipped{
		Reason: "'Drop And Execute New Binary In Container' is applicable only to containers.",
	}
}
