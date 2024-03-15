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
	ReadShellConfigurationFile,
	events.WithDisabled(), // this rules is not included in falco_rules.yaml (stable rules), so disable the action
)

func ReadShellConfigurationFile(h events.Helper) error {
	shellConfigFiles := []string{
		"/etc/bashrc",
		"/etc/profile",
		"/etc/csh.cshrc",
		"/etc/csh.login",
	}

	var errRead error

	// Iterate over shellConfigFiles until a file is successfully opened.
	for _, configFile := range shellConfigFiles {
		file, err := os.Open(configFile)
		if err == nil {
			h.Log().Infof("A shell configuration file %s was read by a non-shell program", configFile)
			defer file.Close()
			return err
		} else if !os.IsNotExist(err) {
			errRead = err
		}
	}

	return errRead
}
