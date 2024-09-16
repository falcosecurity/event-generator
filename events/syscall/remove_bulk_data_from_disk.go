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
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(RemoveBulkDataFromDisk)

func RemoveBulkDataFromDisk(h events.Helper) error {
	shred, err := exec.LookPath("shred")
	if err != nil {
		// if we don't have a shred, just bail
		return &events.ErrSkipped{
			Reason: "shred executable file not found in $PATH",
		}
	}

	// create a unique file under temp directory
	file, err := os.CreateTemp("", "falco-event-generator-syscall-RemoveBulkDataFromDisk-")
	if err != nil {
		return err
	}

	if err := os.WriteFile(file.Name(), []byte("bulk data content"), os.FileMode(0600)); err != nil {
		return err
	}

	// shred the file content
	cmd := exec.Command(shred, "-u", file.Name())
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}

	return nil
}
