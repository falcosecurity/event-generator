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
	"syscall"

	"github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(PtraceAttachedToProcess)

func PtraceAttachedToProcess(h events.Helper) error {
	// Start a dummy process
	cmd := exec.Command("sleep", "3600")
	if err := cmd.Start(); err != nil {
		h.Log().WithError(err).Error("Failed to start dummy process")
		return err
	}
	pid := cmd.Process.Pid

	h.Log().Infof("Attached to dummy process with PID %d using PTRACE_ATTACH", pid)

	defer syscall.PtraceDetach(pid)
	defer cmd.Process.Kill()

	// Attach to the target process using PTRACE_ATTACH
	return syscall.PtraceAttach(pid)
}
