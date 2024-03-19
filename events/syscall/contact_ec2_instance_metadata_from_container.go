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
	"github.com/falcosecurity/event-generator/events"
	"os/exec"
)

var _ = events.Register(
	ContactEC2InstanceMetadataServiceFromContainer,
	events.WithDisabled(), // this rule is not included in falco_rules.yaml (stable rules), so disable the action
)

func ContactEC2InstanceMetadataServiceFromContainer(h events.Helper) error {
	if h.InContainer() {
		path, err := exec.LookPath("nc")
		if err != nil {
			// If we don't have an netcat, just bail
			return &events.ErrSkipped{
				Reason: "netcat utility not found in path",
			}
		}
		// The IP address 169.254.169.254 is reserved for the Cloud Instance Metadata Service,
		// a common endpoint used by cloud instances (GCP, AWS and Azure) to access
		// metadata about the instance itself. Detecting attempts to communicate with this
		// IP address from a container can indicate potential unauthorized access to
		// sensitive cloud infrastructure metadata.

		cmd := exec.Command("timeout", "1s", path, "169.254.169.254", "80")

		if err := cmd.Run(); err != nil {
			return err
		}
	}
	return &events.ErrSkipped{
		Reason: "'Contact EC2 Instance Metadata Service From Container' is applicable only to containers.",
	}
}
