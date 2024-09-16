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

	"github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(
	WriteBelowEtc,
	events.WithDisabled(), // this rules is not included in falco_rules.yaml (stable rules), so disable the action
)

func WriteBelowEtc(h events.Helper) error {
	// ensure /etc exists
	if _, err := os.Stat("/etc"); os.IsNotExist(err) {
		if err := os.Mkdir("/etc", os.FileMode(0755)); err != nil {
			return err
		}
		// remove /etc directory
		defer func() {
			if err := os.RemoveAll("/etc"); err != nil {
				h.Log().WithError(err).Error("failed to remove /etc directory")
			}
		}()
	}

	// create a unique file under /etc directory
	file, err := os.CreateTemp("/etc", "falco-event-generator-syscall-WriteBelowEtc-")
	if err != nil {
		return err
	}
	defer func() {
		if err := os.Remove(file.Name()); err != nil {
			h.Log().WithError(err).Error("failed to remove temp file")
		}
	}()

	return nil
}
