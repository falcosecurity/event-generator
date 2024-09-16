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
	"path/filepath"
	"strings"

	"github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(CreateHardlinkOverSensitiveFiles)

func CreateHardlinkOverSensitiveFiles(h events.Helper) error {
	ln, err := exec.LookPath("ln")
	if err != nil {
		// if we don't have a ln, just bail
		return &events.ErrSkipped{
			Reason: "ln executable file not found in $PATH",
		}
	}

	// create a unique temp directory
	tmpDir, err := os.MkdirTemp("", "falco-event-generator-syscall-CreateHardlinkOverSensitiveFiles-")
	if err != nil {
		return err
	}
	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			h.Log().WithError(err).Error("failed to remove temp directory")
		}
	}()

	shadowLink := filepath.Join(tmpDir, "shadow_link")

	// create a hard link to /etc/shadow file
	// note: directory hard links are not allowed
	cmd := exec.Command(ln, "-v", "/etc/shadow", shadowLink)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}

	// read hard-linked /etc/shadow file
	if _, err := os.ReadFile(shadowLink); err != nil {
		return err
	}

	return nil
}
