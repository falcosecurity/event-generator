// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The Falco Authors
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

package verify

import (
	"fmt"
	"os"

	"github.com/go-logr/logr"
	"github.com/spf13/cobra"

	"github.com/falcosecurity/event-generator/cmd/suite/config"
	"github.com/falcosecurity/event-generator/cmd/suite/test"
	"github.com/falcosecurity/event-generator/pkg/envvar"
)

const (
	longDescriptionPrefaceTemplate = `%s.
It is possible to provide the YAML description in multiple ways. The order of evaluation is the following:
1) If --%s=<file_path> and/or --%s=<dir_path> flags are/is provided, it is read from the file(s) at <file_path> and/or contained in <dir_path>
2) If the --%s=<description> flag is provided, it is read from the <description> string
3) Otherwise, it is read from standard input`
	longDescriptionHeading = "Verify the test(s) YAML description"
)

var (
	longDescription = fmt.Sprintf(longDescriptionPrefaceTemplate, longDescriptionHeading,
		config.DescriptionFileFlagName, config.DescriptionDirFlagName, config.DescriptionFlagName)
)

// CommandWrapper wraps the command and stores the associated flag values.
type CommandWrapper struct {
	Command       *cobra.Command
	envKeysPrefix string
	suiteEnvKey   string

	// Flags
	//
	// testsDescriptionFiles is the list of pathnames of files containing the YAML tests descriptions. If
	// testsDescription is provided, this is empty.
	testsDescriptionFiles []string
	// testsDescriptionDirs is the list of pathnames of directories containing the YAML tests description files. If
	// testsDescription is provided, this is empty.
	testsDescriptionDirs []string
	// testsDescription is the YAML tests description. If testsDescriptionFiles or testsDescriptionDirs are provided,
	// this is empty.
	testsDescription string
}

// New creates a new verify command.
func New(suiteEnvKey, envKeysPrefix string) *CommandWrapper {
	cw := &CommandWrapper{envKeysPrefix: envKeysPrefix, suiteEnvKey: suiteEnvKey}
	c := &cobra.Command{
		Use:               "verify",
		Short:             longDescriptionHeading,
		Long:              longDescription,
		DisableAutoGenTag: true,
		Run:               cw.run,
	}
	cw.Command = c
	cw.initCommandFlags()
	return cw
}

// initCommandFlags initializes the command's flags.
func (cw *CommandWrapper) initCommandFlags() {
	cmd := cw.Command
	flags := cmd.Flags()

	flags.StringSliceVarP(&cw.testsDescriptionFiles, config.DescriptionFileFlagName, "f", nil,
		"The pathnames of tests description YAML files specifying the tests to be verified. Multiple pathnames can be "+
			"specified as a comma-separated list. The flag can be specified multiple times. Pathnames are evaluated "+
			"in order of appearance")
	flags.StringSliceVarP(&cw.testsDescriptionDirs, config.DescriptionDirFlagName, "d", nil,
		"The pathnames of directories containing tests description YAML files specifying the tests to be verified. "+
			"Sub-directories of the provided pathnames are not recursively loaded. Only files with YAML extensions "+
			"are loaded. Multiple pathnames can be specified as a comma-separated list. The flag can be specified "+
			"multiple times. Pathnames are evaluated in order of appearance")
	flags.StringVar(&cw.testsDescription, config.DescriptionFlagName, "",
		"The YAML-formatted tests description string specifying the tests to be verified")
	cmd.MarkFlagsMutuallyExclusive(config.DescriptionFileFlagName, config.DescriptionFlagName)
	cmd.MarkFlagsMutuallyExclusive(config.DescriptionDirFlagName, config.DescriptionFlagName)
}

func (cw *CommandWrapper) run(cmd *cobra.Command, _ []string) {
	ctx := cmd.Context()
	logger, err := logr.FromContext(ctx)
	if err != nil {
		panic(fmt.Sprintf("logger unconfigured: %v", err))
	}

	logger = logger.WithName("main")

	// Note: keep the following in sync with the corresponding code in "test" package.
	reservedEnvKeyPrefixes := []string{envvar.KeyFromFlagName(cw.envKeysPrefix, "")}
	reservedEnvKeys := []string{cw.suiteEnvKey}
	if _, err := test.LoadSuites(logger, false, cw.testsDescriptionFiles, cw.testsDescriptionDirs,
		cw.testsDescription, reservedEnvKeyPrefixes, reservedEnvKeys); err != nil {
		// Do not use the logger here, as it will mess the already-formatted error message.
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
