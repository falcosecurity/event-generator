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

var _ = events.Register(LinuxKernelModuleInjection)

func LinuxKernelModuleInjection(h events.Helper) error {
	if h.InContainer() {
		// Shell script content
		scriptContent := `#!/bin/bash

		# Run lsmod and pipe the output to awk to extract the first module name
		module_name=$(lsmod | awk 'NR==2{print $1}')
		
		# Run modinfo on the first module and grab the module path
		file_path=$(modinfo "$module_name" | awk -F ': ' '/filename/ {print $2}')
		
		# Run insmod with the module path
		sudo insmod $file_path
		`

		scriptFileName := "temp_script.sh"
		if err := os.WriteFile(scriptFileName, []byte(scriptContent), 0755); err != nil {
			h.Log().WithError(err).Error("Error writing script file")
			return err
		}
		defer os.Remove(scriptFileName) // Remove file after function return

		// Set execute permission on script file
		if err := os.Chmod(scriptFileName, 0755); err != nil {
			h.Log().WithError(err).Error("Error setting execute permission on script file")
			return err
		}

		// Execute script file with its full path
		cmd := exec.Command("./" + scriptFileName)
		if err := cmd.Run(); err != nil {
			h.Log().WithError(err).Error("Error running script file")
			return err
		}
	}
	return nil
}
