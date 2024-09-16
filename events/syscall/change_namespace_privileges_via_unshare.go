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
	"os/exec"
	"strings"

	"github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(
	ChangeNamespacePrivilegesViaUnshare,
	events.WithDisabled(), // this rules is not included in falco_rules.yaml (stable rules), so disable the action
)

func ChangeNamespacePrivilegesViaUnshare(h events.Helper) error {
	if !h.InContainer() {
		return &events.ErrSkipped{
			Reason: "only applicable to containers",
		}
	}

	// read the CapEff value from /proc/self/status
	capEffValueBytes, err := exec.Command("sh", "-c", "cat /proc/self/status | grep CapEff | awk '{print $2}'").Output()
	if err != nil {
		return err
	}

	// convert the CapEff value to a string and trim whitespace
	capEffValue := strings.TrimSpace(string(capEffValueBytes))

	// check whether CAP_SYS_ADMIN capability exists in the decoded CapEff value
	hasCAPSysAdmin, err := checkCapability(capEffValue, "cap_sys_admin")
	if err != nil {
		return err
	}

	if hasCAPSysAdmin {
		return &events.ErrSkipped{
			Reason: "non-privileged container required",
		}
	}

	unshare, err := exec.LookPath("unshare")
	if err != nil {
		// if we don't have an unshare, just bail
		return &events.ErrSkipped{
			Reason: "unshare executable file not found in $PATH",
		}
	}

	// note: to trigger the rule, do not pass any arguments to unshare
	cmd := exec.Command(unshare)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}

	return nil
}
