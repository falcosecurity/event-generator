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
	"fmt"
	"os"

	"github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(
	ModifyBinaryDirs,
	events.WithDisabled(), // this rules is not included in falco_rules.yaml (stable rules), so disable the action
)

func ModifyBinaryDirs(h events.Helper) error {
	org := "/bin/true"

	// generate new "random" binary name
	new := fmt.Sprintf("%s.falco-event-generator-syscall-ModifyBinaryDirs-%s", org, randomString(6))

	if err := os.Rename(org, new); err != nil {
		// to trigger the rule, it is enough to try, so we ignore permission denied errors
		if errors.Is(err, os.ErrPermission) {
			return nil
		}
		return err
	}
	defer func() {
		if err := os.Rename(new, org); err != nil {
			h.Log().WithError(err).Error("failed to restore the original binary")
		}
	}()

	return nil
}
