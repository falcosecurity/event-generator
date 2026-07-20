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

package render

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-logr/logr"
	"github.com/spf13/cobra"

	"github.com/falcosecurity/event-generator/cmd/suite/config"
	"github.com/falcosecurity/event-generator/pkg/envvar"
	"github.com/falcosecurity/event-generator/pkg/test/loader"
)

const (
	longDescriptionPrefaceTemplate = `%s.
The rendering process instantiates any template present in the YAML description.
It is possible to provide the YAML description in multiple ways. The order of evaluation is the following:
1) If --%s=<file_path> and/or --%s=<dir_path> flags are/is provided, it is read from the file(s) at <file_path> and/or contained in <dir_path>
2) If the --%s=<description> flag is provided, it is read from the <description> string
3) Otherwise, it is read from standard input
For each YAML description source, a separate YAML document is written to output. Each document is annotated with a comment indicating the source name.
`
	longDescriptionHeading = "Render the test(s) YAML description and display it to output"
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
	// printTestsCount indicates if the user just want the tool to out-put the total number of tests.
	printTestsCount bool
}

// New creates a new render command.
func New(suiteEnvKey, envKeysPrefix string) *CommandWrapper {
	cw := &CommandWrapper{envKeysPrefix: envKeysPrefix, suiteEnvKey: suiteEnvKey}
	c := &cobra.Command{
		Use:               "render",
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
		"The pathnames of tests description YAML files specifying the tests to be rendered. Multiple pathnames can be "+
			"specified as a comma-separated list. The flag can be specified multiple times. Pathnames are evaluated "+
			"in order of appearance")
	flags.StringSliceVarP(&cw.testsDescriptionDirs, config.DescriptionDirFlagName, "d", nil,
		"The pathnames of directories containing tests description YAML files specifying the tests to be rendered. "+
			"Sub-directories of the provided pathnames are not recursively loaded. Only files with YAML extensions "+
			"are loaded. Multiple pathnames can be specified as a comma-separated list. The flag can be specified "+
			"multiple times. Pathnames are evaluated in order of appearance")
	flags.StringVar(&cw.testsDescription, config.DescriptionFlagName, "",
		"The YAML-formatted tests description string specifying the tests to be rendered")
	cmd.MarkFlagsMutuallyExclusive(config.DescriptionFileFlagName, config.DescriptionFlagName)
	cmd.MarkFlagsMutuallyExclusive(config.DescriptionDirFlagName, config.DescriptionFlagName)
	flags.BoolVar(&cw.printTestsCount, "count", false, "Prints the total number of tests and exit")
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
	testsDescs, err := loadTests(logger, cw.testsDescriptionFiles, cw.testsDescriptionDirs, cw.testsDescription,
		reservedEnvKeyPrefixes, reservedEnvKeys)
	if err != nil {
		logger.Error(err, "Error loading tests")
		os.Exit(1)
	}

	// If the user requested the tests count, just print it and return.
	if cw.printTestsCount {
		testsCount := 0
		for _, testDesc := range testsDescs {
			testsCount += len(testDesc.desc.Tests)
		}
		fmt.Println(testsCount)
		return
	}

	w := os.Stdout
	for _, testsDesc := range testsDescs {
		source := testsDesc.source
		logger := logger.WithValues("source", source)
		header := fmt.Sprintf("---\n# source: %s\n", source)
		if _, err := w.WriteString(header); err != nil {
			logger.Error(err, "Error writing tests description header")
			os.Exit(1)
		}

		if err := testsDesc.desc.Write(w); err != nil {
			logger.Error(err, "Error writing tests description")
			os.Exit(1)
		}
	}
}

type sourcedDescription struct {
	source string
	desc   *loader.Description
}

// loadTests loads tests description(s) from a different source, depending on the content of the provided values:
//   - if the provided descriptionFilePaths or descriptionDirPaths are not empty, they are loaded both from the
//     specified files (if any) and from the YAML files (if any) in the specified directories (if any);
//   - if the provided description is not empty, they are loaded from its content;
//   - otherwise, they are loaded from standard input.
func loadTests(logger logr.Logger, descriptionFilePaths, descriptionDirPaths []string, description string,
	reservedEnvKeyPrefixes, reservedEnvKeys []string) ([]*sourcedDescription, error) {
	descLoader := loader.New(reservedEnvKeyPrefixes, reservedEnvKeys)

	// Load from the specified files or directories.
	if len(descriptionFilePaths) > 0 || len(descriptionDirPaths) > 0 {
		var testsDescs []*sourcedDescription
		for _, descriptionDirPath := range descriptionDirPaths {
			descs, err := loadTestsFromDescriptionDir(logger, descLoader, descriptionDirPath)
			if err != nil {
				return nil, fmt.Errorf("error loading description directory %q: %w", descriptionDirPath, err)
			}
			testsDescs = append(testsDescs, descs...)
		}

		for _, descriptionFilePath := range descriptionFilePaths {
			desc, err := loadTestsFromDescriptionFile(logger, descLoader, descriptionFilePath)
			if err != nil {
				return nil, fmt.Errorf("error loading description file %q: %w", descriptionFilePath, err)
			}
			testsDescs = append(testsDescs, desc)
		}

		return testsDescs, nil
	}

	// Load from the provided description string.
	if description != "" {
		desc, err := descLoader.Load(strings.NewReader(description))
		if err != nil {
			return nil, fmt.Errorf("error loading from description flag: %w", err)
		}
		return []*sourcedDescription{{source: "<description flag>", desc: desc}}, nil
	}

	// Load from standard input.
	desc, err := descLoader.Load(os.Stdin)
	if err != nil {
		return nil, fmt.Errorf("error loading from stdin: %w", err)
	}
	return []*sourcedDescription{{source: "<stdin>", desc: desc}}, nil
}

// loadTestsFromDescriptionDir loads tests descriptions from YAML files inside the directory at the provided path and
// returns them.
func loadTestsFromDescriptionDir(logger logr.Logger, descLoader *loader.Loader,
	descriptionDirPath string) ([]*sourcedDescription, error) {
	descriptionDirPath = filepath.Clean(descriptionDirPath)
	dirEntries, err := os.ReadDir(descriptionDirPath)
	if err != nil {
		return nil, fmt.Errorf("error reading entries in directory %q: %w", descriptionDirPath, err)
	}

	testsDescs := make([]*sourcedDescription, 0, len(dirEntries))

	for _, dirEntry := range dirEntries {
		if dirEntry.IsDir() {
			continue
		}

		name := dirEntry.Name()
		if !strings.HasSuffix(name, ".yaml") {
			continue
		}

		descriptionFilePath := filepath.Join(descriptionDirPath, name)
		testsDesc, err := loadTestsFromDescriptionFile(logger, descLoader, descriptionFilePath)
		if err != nil {
			return nil, fmt.Errorf("error loading description file %q: %w", name, err)
		}

		testsDescs = append(testsDescs, testsDesc)
	}

	return testsDescs, nil
}

// loadTestsFromDescriptionFile loads tests description from the file at the provided path and returns it. The
// associated name is the "cleaned" version of the provided path (see filepath.Clean).
func loadTestsFromDescriptionFile(logger logr.Logger, descLoader *loader.Loader,
	descriptionFilePath string) (*sourcedDescription, error) {
	descriptionFilePath = filepath.Clean(descriptionFilePath)
	descriptionFile, err := os.Open(descriptionFilePath)
	if err != nil {
		return nil, fmt.Errorf("error opening file path %q: %w", descriptionFilePath, err)
	}
	defer func() {
		if err := descriptionFile.Close(); err != nil {
			logger.Error(err, "Error closing description file", "path", descriptionFilePath)
		}
	}()

	desc, err := descLoader.Load(descriptionFile)
	if err != nil {
		return nil, err
	}

	return &sourcedDescription{source: descriptionFilePath, desc: desc}, nil
}
