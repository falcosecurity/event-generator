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

var _ = events.Register(ExecutionFromDevShm)

func ExecutionFromDevShm(h events.Helper) error {
	scriptPath := "/dev/shm/example_script-created-by-falco-event-generator.sh"
	scriptContent := "#!/bin/bash\n echo 'hello world'"

	// Check if /dev exists
	if _, err := os.Stat("/dev"); os.IsNotExist(err) {
		if err := os.Mkdir("/dev/shm", 0755); err != nil {
			return err
		}
		defer os.RemoveAll("/dev") // Remove dev directory
	}

	// Given /dev exists check if /shm exists
	if _, err := os.Stat("/dev/shm"); os.IsNotExist(err) {
		if err := os.Mkdir("/dev/shm", 0755); err != nil {
			return err
		}
		defer os.RemoveAll("/dev/shm") // Remove /shm directory only
	}

	// Set execute permission on the file
	if err := os.WriteFile(scriptPath, []byte(scriptContent), 0755); err != nil {
		return err
	}

	cmd := exec.Command("sh", "-c", scriptPath) // Execute script file
	defer os.Remove(scriptPath)                 // Remove script file
	return cmd.Run()
}
