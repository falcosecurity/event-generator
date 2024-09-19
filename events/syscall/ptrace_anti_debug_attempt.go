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

var _ = events.Register(PtraceAntiDebugAttempt)

func PtraceAntiDebugAttempt(h events.Helper) error {
	// start a dummy process which sleeps for 1hr
	cmd := exec.Command("sleep", "3600")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Ptrace: true, // This is equivalent to calling PTRACE_TRACEME in the child
	}
	if err := cmd.Start(); err != nil {
		h.Log().WithError(err).Error("failed to start dummy process")
		return err
	}

	// kill the dummy process
	defer func() {
		if err := cmd.Process.Kill(); err != nil {
			h.Log().WithError(err).Error("failed to kill dummy process")
		}
		// wait for the dummy process to exit, to avoid creating a zombie
		_ = cmd.Wait()
	}()

	return nil
}
