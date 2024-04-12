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
	"bytes"
	"os"
	"os/exec"
	"strings"

	"github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(DetectReleaseAgentFileContainerEscapes)

func DetectReleaseAgentFileContainerEscapes(h events.Helper) error {
	if h.InContainer() {
		// Read the CapEff value from /proc/self/status
		capEffValueBytes, err := exec.Command("sh", "-c", "cat /proc/self/status | grep CapEff | awk '{print $2}'").Output()
		if err != nil {
			return err
		}

		// Convert the CapEff value to a string and trim whitespace
		capEffValue := strings.TrimSpace(string(capEffValueBytes))

		// user.uid=0 or thread.cap_effective contains CAP_DAC_OVERRIDE reuired condition
		if os.Getuid() != 0 {
			hasCAPDacOverride, err := checkCapability(capEffValue, "cap_dac_override")
			if err != nil {
				return err
			}
			if !hasCAPDacOverride {
				return &events.ErrSkipped{
					Reason: "Conatiner with root user or CAP_DAC_OVERRIDE capability is required to execute this event",
				}
			}
		}

		// Check whether CAP_SYS_ADMIN capability exists in the decoded CapEff value
		hasCAPSysAdmin, err := checkCapability(capEffValue, "cap_sys_admin")
		if err != nil {
			return err
		}
		if hasCAPSysAdmin {
			// open_write and fd.name endswith release_agent
			cmd := exec.Command("echo", "hello world", ">", "release_agent")
			if err := cmd.Run(); err != nil {
				return err
			}
			h.Log().Infof("Container escape using release_agent file")
			return nil
		}
		return &events.ErrSkipped{
			Reason: "Conatiner with cap_sys_admin capability is required to execute this event",
		}
	}
	return &events.ErrSkipped{
		Reason: "'Detect release_agent File Container Escapes' rule is only for containers",
	}
}

// This function checks wether given capability exists or not by decoding the given hex
// For ex: Below is the output when we run capsh --decode=0x0000000000000003
// 0x0000000000000003=cap_chown,cap_dac_override
func checkCapability(hexValue string, capability string) (bool, error) {
	capsh, err := exec.LookPath("capsh")
	if err != nil {
		return false, &events.ErrSkipped{
			Reason: "capsh utility is required to execute this event",
		}
	}
	cmd := exec.Command(capsh, "--decode="+hexValue)

	// Capture the output of the command
	var output bytes.Buffer
	cmd.Stdout = &output
	if err := cmd.Run(); err != nil {
		return false, err
	}

	// Convert output to a string
	outputStr := output.String()

	// Check if the output contains the given capability
	return strings.Contains(outputStr, capability), nil
}
