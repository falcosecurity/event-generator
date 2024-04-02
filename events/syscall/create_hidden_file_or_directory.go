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
	CreateHiddenFileOrDirectory,
	events.WithDisabled(), // this rule is not included in falco_rules.yaml (stable rules), so disable the action
)

func CreateHiddenFileOrDirectory(h events.Helper) error {
	// Create a hidden directory
	const directoryname = "/.created-by-event-generator"
	h.Log().Infof("Created a hidden directory %s", directoryname)
	defer os.Remove(directoryname) // Remove after function return
	return os.Mkdir(directoryname, 0755)
}
