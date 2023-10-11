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
	"github.com/falcosecurity/event-generator/events"

	"os/exec"
)

var _ = events.Register(
	ScheduleCronJobs,
	events.WithDisabled(), // the rule is not enabled by default, so disable the action too
)

func ScheduleCronJobs(h events.Helper) error {
	// This just lists crons, but sufficies to trigger the event
	// Cron detection is not enabled by default, see `consider_all_cron_jobs` in rules.yaml

	path, err := exec.LookPath("crontab")
	if err != nil {
		// if we don't have a crontab, just bail
		return &events.ErrSkipped{
			Reason: "crontab utility not found in path",
		}
	}
	cmd := exec.Command(path, "-l")
	err = cmd.Run()

	// silently ignore crontab exit status 1
	if exitErr, isExitErr := err.(*exec.ExitError); isExitErr {
		h.Log().WithError(exitErr).Debug("silently ignore exit status")
		return nil
	}
	return err
}
