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
	"context"
	"os/exec"
	"time"

	"github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(
	ContactEC2InstanceMetadataServiceFromContainer,
	events.WithDisabled(), // this rule is not included in falco_rules.yaml (stable rules), so disable the action
)

func ContactEC2InstanceMetadataServiceFromContainer(h events.Helper) error {
	if !h.InContainer() {
		return &events.ErrSkipped{
			Reason: "only applicable to containers",
		}
	}

	nc, err := exec.LookPath("nc")
	if err != nil {
		// if we don't have a netcat, just bail
		return &events.ErrSkipped{
			Reason: "netcat executable file not found in $PATH",
		}
	}

	// The IP address 169.254.169.254 is reserved for the Cloud Instance Metadata Service,
	// a common endpoint used by cloud instances (GCP, AWS and Azure) to access
	// metadata about the instance itself. Detecting attempts to communicate with this
	// IP address from a container can indicate potential unauthorized access to
	// sensitive cloud infrastructure metadata.
	// note: executing the following command might fail, but enough to trigger the rule, so we ignore any error
	if err := runCmd(context.Background(), 1*time.Second, nc, "169.254.169.254", "80"); err != nil {
		h.Log().WithError(err).Debug("failed to run netcat command (might be ok)")
	}

	return nil
}
