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
	"syscall"

	"github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(PtraceAntiDebugAttempt)

func PtraceAntiDebugAttempt(h events.Helper) error {
	// Attempt to call ptrace with PTRACE_TRACEME argument
	_, _, err := syscall.Syscall(syscall.SYS_PTRACE, syscall.PTRACE_TRACEME, 0, 0)
	if err != 0 {
		h.Log().WithError(err).Error("Failed to call ptrace with PTRACE_TRACEME argument")
		return err
	}

	h.Log().Infof("Successfully called ptrace with PTRACE_TRACEME argument")
	return nil
}
