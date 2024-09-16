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
	"os/exec"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(
	ChangeThreadNamespace,
	events.WithDisabled(), // this rules is not included in falco_rules.yaml (stable rules), so disable the action
)

func ChangeThreadNamespace(h events.Helper) error {
	if h.InContainer() {
		// skip if container does not have CAP_SYS_ADMIN capability, fallthrough in case of error
		// read the CapEff value from /proc/self/status
		if capEffValueBytes, err := exec.Command("sh", "-c", "cat /proc/self/status | grep CapEff | awk '{print $2}'").Output(); err == nil {
			// convert the CapEff value to a string and trim whitespace
			capEffValue := strings.TrimSpace(string(capEffValueBytes))
			// check whether CAP_SYS_ADMIN capability exists in the decoded CapEff value
			if hasCAPSysAdmin, err := checkCapability(capEffValue, "cap_sys_admin"); err == nil && !hasCAPSysAdmin {
				return &events.ErrSkipped{
					Reason: "privileged container required",
				}
			}
		}
	}
	// it doesn't matter that the arguments to Setns are bogus
	// it's the attempt to call it that will trigger the rule
	if err := unix.Setns(0, 0); err != nil {
		h.Log().WithError(err).Debug("failed to call setns (this is expected)")
	}

	return nil
}
