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

var _ = events.Register(CreateSymlinkOverSensitiveFiles)

func CreateSymlinkOverSensitiveFiles(h events.Helper) error {
	path, err := exec.LookPath("ln")
	if err != nil {
		// if we don't have a ln, just bail
		return &events.ErrSkipped{
			Reason: "ln utility not found in path",
		}
	}

	tmpDir, err := os.MkdirTemp(os.TempDir(), "event-generator-syscall-CreateSymlinkOverSensitiveFiles")
	if err != nil {
		return err
	}
	defer os.ReadDir(tmpDir)

	cmd := exec.Command(path, "-s", "/etc", tmpDir+"/etc_link")
	return cmd.Run()
}
