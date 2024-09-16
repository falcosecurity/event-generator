//go:build linux
// +build linux

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

	"golang.org/x/sys/unix"

	"github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(FilelessExecutionViaMemfdCreate)

func FilelessExecutionViaMemfdCreate(h events.Helper) error {
	// Event-generator executable path
	exePath := h.ExePath()

	// Read the event-generator executable into memory
	binaryData, err := os.ReadFile(exePath)
	if err != nil {
		h.Log().WithError(err).Error("failed to read binary file")
		return err
	}

	// Load the binary into memory
	fd, err := unix.MemfdCreate("program", 0)
	if err != nil {
		h.Log().WithError(err).Error("failed to create memory file descriptor")
		return err
	}
	_, err = unix.Write(fd, binaryData)
	if err != nil {
		h.Log().WithError(err).Error("failed to write binary data to memory")
		return err
	}
	defer func() {
		if err := unix.Close(fd); err != nil {
			h.Log().WithError(err).Error("failed to close memory file descriptor")
		}
	}()

	// Execute the binary from memory
	cmd := exec.Command("/proc/self/fd/"+fmt.Sprintf("%d", fd), "run", "helper.DoNothing")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}

	return nil
}
