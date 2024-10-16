//go:build linux
// +build linux

// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.
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

	"github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(
	ScheduleCronJobs,
	events.WithDisabled(), // the rule is not enabled by default, so disable the action too
)

func ScheduleCronJobs(h events.Helper) error {
	crontab, err := exec.LookPath("crontab")
	if err != nil {
		// if we don't have a crontab, just bail
		return &events.ErrSkipped{
			Reason: "crontab executable file not found in $PATH",
		}
	}

	// this just lists crons, but enough to trigger the rule, so we ignore crontab exit code 1
	err = exec.Command(crontab, "-l").Run()
	if ee, ok := err.(*exec.ExitError); ok && ee.ProcessState.ExitCode() == 1 {
		h.Log().WithError(err).Debug("crontab command failed with exit code 1 (might be ok)")
		return nil
	}

	return err
}
