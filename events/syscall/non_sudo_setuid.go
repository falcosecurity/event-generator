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
	"errors"
	"os"

	"github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(
	NonSudoSetuid,
	events.WithDisabled(), // this rules is not included in falco_rules.yaml (stable rules), so disable the action
)

func NonSudoSetuid(h events.Helper) error {
	// ensure the process is spawned, otherwise we might hit unexpected side effect issues with becameUser()
	if h.Spawned() {
		h.Log().Debug("first setuid to something non-root, then try to setuid back to root")
		if err := becameUser(h, "daemon"); err != nil {
			// to trigger the rule, it is enough to try, so we ignore permission denied errors
			if errors.Is(err, os.ErrPermission) {
				return nil
			}
			return err
		}
		// note: executing the following command might fail, but enough to trigger the rule, so we ignore any error
		if err := becameUser(h, "root"); err != nil {
			h.Log().WithError(err).Debug("failed to setuid back to root (might be ok)")
		}
		return nil
	}
	return h.SpawnAsWithSymlink("child", "syscall.NonSudoSetuid")
}
