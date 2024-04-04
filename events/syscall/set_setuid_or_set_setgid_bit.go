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
	"os"
	"os/exec"

	"github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(
	SetSetuidorSetgidbit,
	events.WithDisabled(), // this rules is not included in falco_rules.yaml (stable rules), so disable the action
)

func SetSetuidorSetgidbit(h events.Helper) error {
	filename := "created-by-falco-event-generator"
	if err := os.WriteFile(filename, nil, 0755); err != nil {
		h.Log().WithError(err).Error("Error Creating an empty file")
		return err
	}
	defer os.Remove(filename) // Remove the file after function return

	// Set setuid bit with this command
	cmd := exec.Command("chmod", "u+s", filename)

	if err := cmd.Run(); err != nil {
		h.Log().WithError(err).Error("Error running chmod commad")
		return err
	}

	return nil
}
