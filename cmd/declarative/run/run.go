// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 The Falco Authors
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

package run

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/falcosecurity/event-generator/cmd/declarative/config"
	"github.com/falcosecurity/event-generator/cmd/declarative/test"
)

const (
	longDescriptionPrefaceTemplate = `%s.
It is possible to provide the YAML description in multiple ways. The order of evaluation is the following:
1) If the --%s=<file_path> flag is provided the description is read from the file at <file_path>
2) If the --%s=<description> flag is provided, the description is read from the <description> string
3) Otherwise, it is read from standard input`
	longDescriptionHeading = "Run test(s) specified via a YAML description"
	warningMessage         = `Warning:
  This command might alter your system. For example, some actions modify files and directories below /bin, /etc, /dev,
  etc... Make sure you fully understand what is the purpose of this tool before running any action.`
)

var (
	longDescriptionPreface = fmt.Sprintf(longDescriptionPrefaceTemplate, longDescriptionHeading,
		config.DescriptionFileFlagName, config.DescriptionFlagName)
	longDescription = fmt.Sprintf("%s\n\n%s", longDescriptionPreface, warningMessage)
)

// New creates a new run command.
func New(commonConf *config.Config) *cobra.Command {
	c := &cobra.Command{
		Use:               "run",
		Short:             longDescriptionHeading,
		Long:              longDescription,
		DisableAutoGenTag: true,
		Run:               test.New(commonConf, true).Command.Run,
	}
	return c
}
