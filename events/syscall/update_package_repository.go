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
	UpdatePackageRepository,
	events.WithDisabled(), // this rules is not included in falco_rules.yaml (stable rules), so disable the action
)

func UpdatePackageRepository(h events.Helper) error {
	path := "/etc/apt/sources.list"

	// Check if the file exists
	if _, err := os.Stat(path); err != nil {
		// If the file doesn't exist, create it and open it in write only mode
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, os.FileMode(0755))
		if err != nil {
			return err
		}
		defer file.Close()
		// Remove file after closing it to free file occupied space
		os.Remove(path)

	} else {
		// If the file exists, open it for writing
		file, err := os.OpenFile(path, os.O_WRONLY, os.FileMode(0755))
		if err != nil {
			return err
		}
		defer file.Close()
	}

	return nil
}
