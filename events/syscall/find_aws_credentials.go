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
	"os"
	"os/exec"
	"strings"

	"github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(FindAwsCredentials)

func FindAwsCredentials(h events.Helper) error {
	find, err := exec.LookPath("find")
	if err != nil {
		// if we don't have a find, just bail
		return &events.ErrSkipped{
			Reason: "find executable file not found in $PATH",
		}
	}

	cmd := exec.Command(find, os.TempDir(), "-maxdepth", "1", "-iname", ".aws/credentials")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}

	return nil
}
