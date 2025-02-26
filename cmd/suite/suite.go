// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 The Falco Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package suite

import (
	"github.com/spf13/cobra"

	"github.com/falcosecurity/event-generator/cmd/suite/config"
	"github.com/falcosecurity/event-generator/cmd/suite/explain"
	"github.com/falcosecurity/event-generator/cmd/suite/run"
	"github.com/falcosecurity/event-generator/cmd/suite/test"
)

// New creates a new suite command.
func New(suiteEnvKey, envKeysPrefix string) *cobra.Command {
	c := &cobra.Command{
		Use:               "suite",
		Short:             "Manage test suites described via YAML files",
		Long:              "Provide sub-commands to work with test suites described via YAML files",
		DisableAutoGenTag: true,
	}

	commonConf := config.New(suiteEnvKey, envKeysPrefix)

	runCmd := run.New(commonConf)
	testCmd := test.New(commonConf, false).Command
	explainCmd := explain.New().Command
	c.AddCommand(runCmd)
	c.AddCommand(testCmd)
	c.AddCommand(explainCmd)
	return c
}
