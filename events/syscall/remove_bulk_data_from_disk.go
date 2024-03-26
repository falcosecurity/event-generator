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

var _ = events.Register(RemoveBulkDataFromDisk)

func RemoveBulkDataFromDisk(h events.Helper) error {
	// Creates temporary data for testing, avoiding critical file deletion.
	filename := "/created-by-falco-event-generator"
	defer os.RemoveAll(filename) // clean up
	if err := os.WriteFile(filename, []byte("bulk data content"), os.FileMode(0755)); err != nil {
		return err
	}

	h.Log().Infof("attempting to run shred command to remove bulk data from disk")
	// Rule triggers regardless of whether the 'shred' utility exists or its outcome
	// Therefore, there's no need to skip the action or report the error in any case
	cmd := exec.Command("shred", "-u", filename)
	cmd.Run()
	return nil
}
