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
	UnexpectedUDPTraffic,
	events.WithDisabled(), // this rules is not included in falco_rules.yaml (stable rules), so disable the action
)

func UnexpectedUDPTraffic(h events.Helper) error {
	nc, err := exec.LookPath("nc")
	if err != nil {
		// if we don't have a netcat, just bail
		return &events.ErrSkipped{
			Reason: "netcat executable file not found in $PATH",
		}
	}

	// note: executing the following command might fail, but enough to trigger the rule, so we ignore any error
	if err := exec.Command("timeout", "1s", nc, "-u", "example.com", "22").Run(); err != nil {
		h.Log().WithError(err).Debug("failed to run nc command (this is expected)")
	}

	return nil
}
