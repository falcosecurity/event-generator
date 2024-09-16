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
	"errors"
	"os/exec"

	"github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(
	SudoPotentialPrivilegeEscalation,
	events.WithDisabled(), // this rules is not included in falco_rules.yaml (stable rules), so disable the action
)

func SudoPotentialPrivilegeEscalation(h events.Helper) error {
	sudoedit, err := exec.LookPath("sudoedit")
	if err != nil {
		// if we don't have a sudoedit, just bail
		return &events.ErrSkipped{
			Reason: "sudoedit executable file not found in $PATH",
		}
	}

	// note: executing the following command might fail, but enough to trigger the rule, so we ignore the exit code 1 error
	err = runAsUser(h, "daemon", sudoedit, "-u", "daemon", "-s", "ls\\")

	// we need to unwrap the error to get the exit code
	unerr := errors.Unwrap(err)
	if unerr == nil {
		unerr = err
	}
	if ee, ok := unerr.(*exec.ExitError); ok && ee.ProcessState.ExitCode() == 1 {
		return &events.ErrSkipped{
			Reason: "sudoedit command failed with exit code 1 (might be ok) - probably patched and not vulnerable to CVE-2021-3156",
		}
	}

	return err
}
