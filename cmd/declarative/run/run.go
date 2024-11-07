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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/falcosecurity/event-generator/pkg/test"
	testbuilder "github.com/falcosecurity/event-generator/pkg/test/builder"
	"github.com/falcosecurity/event-generator/pkg/test/loader"
	resbuilder "github.com/falcosecurity/event-generator/pkg/test/resource/builder"
	"github.com/falcosecurity/event-generator/pkg/test/runner"
	runnerbuilder "github.com/falcosecurity/event-generator/pkg/test/runner/builder"
	stepbuilder "github.com/falcosecurity/event-generator/pkg/test/step/builder"
	sysbuilder "github.com/falcosecurity/event-generator/pkg/test/step/syscall/builder"
)

// CommandWrapper is a thin wrapper around the cobra command.
type CommandWrapper struct {
	envKeysPrefix     string
	declarativeEnvKey string
	// descriptionFileEnvKey is the environment variable key corresponding to descriptionFileFlagName.
	descriptionFileEnvKey string
	// descriptionEnvKey is the environment variable key corresponding to descriptionFlagName.
	descriptionEnvKey string
	// procLabelEnvKey is the environment variable key corresponding to procLabelFlagName.
	procLabelEnvKey string
	Command         *cobra.Command
}

const (
	// descriptionFileFlagName is the name of the flag allowing to specify the path of the file containing the YAML
	// tests description.
	descriptionFileFlagName = "description-file"
	// descriptionFlagName is the name of the flag allowing to specify the YAML tests description.
	descriptionFlagName = "description"
	// procLabelFlagName is the name of the flag allowing to specify a process label in the form
	// test<testIndex>,child<childIndex>.
	procLabelFlagName = "proc-label"
)

const longDescriptionPrefaceTemplate = `Run tests(s) specified via a YAML description.

It is possible to provide the YAML description in multiple ways. The order of evaluation is the following:
1) If the --%s=<file_path> flag is provided the description is read from the file at <file_path>
2) If the --%s=<description> flag is provided, the description is read from the <description> string
3) Otherwise, it is read from standard input`

var longDescriptionPreface = fmt.Sprintf(longDescriptionPrefaceTemplate, descriptionFileFlagName, descriptionFlagName)

const warningMessage = `Warning:
  This command might alter your system. For example, some actions modify files and directories below /bin, /etc, /dev,
  etc... Make sure you fully understand what is the purpose of this tool before running any action.`

var longDescription = fmt.Sprintf("%s\n\n%s", longDescriptionPreface, warningMessage)

// New creates a new run command.
func New(declarativeEnvKey, envKeysPrefix string) *CommandWrapper {
	cw := &CommandWrapper{
		declarativeEnvKey:     declarativeEnvKey,
		envKeysPrefix:         envKeysPrefix,
		descriptionFileEnvKey: envKeyFromFlagName(envKeysPrefix, descriptionFileFlagName),
		descriptionEnvKey:     envKeyFromFlagName(envKeysPrefix, descriptionFlagName),
		procLabelEnvKey:       envKeyFromFlagName(envKeysPrefix, procLabelFlagName),
	}

	c := &cobra.Command{
		Use:               "run",
		Short:             "Run test(s) specified via a YAML description",
		Long:              longDescription,
		DisableAutoGenTag: true,
		Run:               cw.run,
	}

	initFlags(c)
	cw.Command = c
	return cw
}

// envKeyFromFlagName converts the provided flag name into the corresponding environment variable key.
func envKeyFromFlagName(envKeysPrefix, flagName string) string {
	s := fmt.Sprintf("%s_%s", envKeysPrefix, strings.ToUpper(flagName))
	s = strings.ToUpper(s)
	return strings.ReplaceAll(s, "-", "_")
}

// initFlags initializes the provided command's flags.
func initFlags(c *cobra.Command) {
	flags := c.Flags()

	flags.StringP(descriptionFileFlagName, "f", "",
		"The tests description YAML file specifying the tests to be run")
	flags.StringP(descriptionFlagName, "d", "",
		"The YAML-formatted tests description string specifying the tests to be run")
	c.MarkFlagsMutuallyExclusive(descriptionFileFlagName, descriptionFlagName)

	flags.StringP(procLabelFlagName, "p", "",
		"(used during process chain building) The process label in the form test<testIndex>.child<childIndex>. "+
			"It is used for logging purposes and to potentially generate the child process label")
	_ = flags.MarkHidden(procLabelFlagName)
}

// processLabelInfo contains information regarding the process label.
type processLabelInfo struct {
	testName   string
	testIndex  int
	childName  string
	childIndex int
}

// run runs the tests from the provided YAML description.
func (cw *CommandWrapper) run(c *cobra.Command, _ []string) {
	ctx := c.Context()
	logger, err := logr.FromContext(ctx)
	if err != nil {
		panic(fmt.Sprintf("logger unconfigured: %v", err))
	}

	flags := c.Flags()

	procLabelInfo, err := parseProcLabel(flags)
	if err != nil {
		logger.Error(err, "Error parsing process label")
		os.Exit(1)
	}

	if procLabelInfo == nil {
		logger = logger.WithName("root")
	} else {
		logger = logger.WithName(procLabelInfo.testName).WithName(procLabelInfo.childName)
	}

	description, err := loadTestsDescription(logger, flags)
	if err != nil {
		logger.Error(err, "Error loading tests description")
		os.Exit(1)
	}

	resourceBuilder, err := resbuilder.New()
	if err != nil {
		logger.Error(err, "Error creating resource builder")
		os.Exit(1)
	}

	syscallBuilder := sysbuilder.New()
	stepBuilder, err := stepbuilder.New(syscallBuilder)
	if err != nil {
		logger.Error(err, "Error creating step builder")
		os.Exit(1)
	}

	testBuilder, err := testbuilder.New(resourceBuilder, stepBuilder)
	if err != nil {
		logger.Error(err, "Error creating test builder")
		os.Exit(1)
	}

	runnerBuilder, err := runnerbuilder.New(testBuilder)
	if err != nil {
		logger.Error(err, "Error creating runner builder")
		os.Exit(1)
	}

	// Prepare parameters shared by runners.
	runnerLogger := logger.WithName("runner")
	runnerEnviron := cw.buildRunnerEnviron(c)
	var runnerProcLabel string
	if procLabelInfo != nil {
		runnerProcLabel = fmt.Sprintf("%s,%s", procLabelInfo.testName, procLabelInfo.childName)
	}

	// Build and run the tests.
	for testIndex := range description.Tests {
		testDesc := &description.Tests[testIndex]

		runnerDescription := &runner.Description{
			Logger:                    runnerLogger,
			Type:                      testDesc.Runner,
			Environ:                   runnerEnviron,
			TestDescriptionEnvKey:     cw.descriptionEnvKey,
			TestDescriptionFileEnvKey: cw.descriptionFileEnvKey,
			ProcLabelEnvKey:           cw.procLabelEnvKey,
			ProcLabel:                 runnerProcLabel,
		}
		runnerInstance, err := runnerBuilder.Build(runnerDescription)
		if err != nil {
			logger.Error(err, "Error creating runner")
			os.Exit(1)
		}

		// If this process belongs to a test process chain, override the logged test index in order to match its
		// absolute index among all the test descriptions.
		if len(description.Tests) == 1 && procLabelInfo != nil {
			testIndex = procLabelInfo.testIndex
		}

		logger := logger.WithValues("testName", testDesc.Name, "testIndex", testIndex)

		logger.Info("Starting test execution...")

		if err := runnerInstance.Run(ctx, testIndex, testDesc); err != nil {
			var resBuildErr *test.ResourceBuildError
			var stepBuildErr *test.StepBuildError
			var resCreationErr *test.ResourceCreationError
			var stepRunErr *test.StepBuildError

			switch {
			case errors.As(err, &resBuildErr):
				logger.Error(resBuildErr.Err, "Error building test resource", "resourceName", resBuildErr.ResourceName,
					"resourceIndex", resBuildErr.ResourceIndex)
			case errors.As(err, &stepBuildErr):
				logger.Error(stepBuildErr.Err, "Error building test step", "stepName", stepBuildErr.StepName,
					"stepIndex", stepBuildErr.StepIndex)
			case errors.As(err, &resCreationErr):
				logger.Error(resCreationErr.Err, "Error creating test resource", "resourceName",
					resCreationErr.ResourceName, "resourceIndex", resCreationErr.ResourceIndex)
			case errors.As(err, &stepRunErr):
				logger.Error(stepRunErr.Err, "Error running test step", "stepName", stepRunErr.StepName, "stepIndex",
					stepRunErr.StepIndex)
			default:
				logger.Error(err, "Error running test")
			}

			os.Exit(1)
		}

		logger.Info("Test execution completed")
	}
}

// buildRunnerEnviron creates a list of string representing the environment, by adding to the current process
// environment all the provided command flags and all the required environment variable needed to enable the runner to
// rerun the current executable with the proper environment configuration.
func (cw *CommandWrapper) buildRunnerEnviron(c *cobra.Command) []string {
	environ := os.Environ()
	environ = cw.appendFlags(environ, c.PersistentFlags(), c.Flags())
	environ = append(environ, fmt.Sprintf("%s=1", cw.declarativeEnvKey))
	return environ
}

// appendFlags appends the provided flag sets' flags to environ and returns the updated environ. Works like the builtin
// append function.
func (cw *CommandWrapper) appendFlags(environ []string, flagSets ...*pflag.FlagSet) []string {
	appendFlag := func(flag *pflag.Flag) {
		keyName := envKeyFromFlagName(cw.envKeysPrefix, flag.Name)
		environ = append(environ, fmt.Sprintf("%s=%s", keyName, flag.Value.String()))
	}
	for _, flagSet := range flagSets {
		flagSet.VisitAll(appendFlag)
	}
	return environ
}

var (
	// procLabelRegex defines the process label format and allows to extract the embedded test and child indexes.
	procLabelRegex    = regexp.MustCompile(`^test(\d+),child(\d+)$`)
	errProcLabelRegex = fmt.Errorf("process label must comply with %q regex", procLabelRegex.String())
)

// parseProcLabel extracts the process label information from the procLabelFlagName flag.
func parseProcLabel(flags *pflag.FlagSet) (*processLabelInfo, error) {
	if !flags.Changed(procLabelFlagName) {
		return nil, nil
	}

	procLabelValue, err := flags.GetString(procLabelFlagName)
	if err != nil {
		return nil, fmt.Errorf("error retrieving %q flag: %w", procLabelFlagName, err)
	}

	match := procLabelRegex.FindStringSubmatch(procLabelValue)
	if match == nil {
		return nil, errProcLabelRegex
	}

	// No errors can occur, since we have already verified through regex that they are numbers.
	testIndex, _ := strconv.Atoi(match[1])
	childIndex, _ := strconv.Atoi(match[2])

	parts := strings.Split(procLabelValue, ",")

	procLabel := &processLabelInfo{
		testName:   parts[0],
		testIndex:  testIndex,
		childName:  parts[1],
		childIndex: childIndex,
	}

	return procLabel, nil
}

// loadTestsDescription loads the YAML tests description from a different source, depending on the provided flags. If
// the descriptionFileFlagName flag is provided, the description is loaded from the specified file; if the
// descriptionFlagName flag is provided, the description is loaded from the flag argument; otherwise, it is loaded from
// standard input.
func loadTestsDescription(logger logr.Logger, flags *pflag.FlagSet) (*loader.Description, error) {
	ldr := loader.New()

	if flags.Changed(descriptionFileFlagName) {
		descriptionFilePath, err := flags.GetString(descriptionFileFlagName)
		if err != nil {
			return nil, fmt.Errorf("error retrieving %q flag: %w", descriptionFileFlagName, err)
		}

		descriptionFilePath = filepath.Clean(descriptionFilePath)
		descriptionFile, err := os.Open(descriptionFilePath)
		if err != nil {
			return nil, fmt.Errorf("error opening description file %q: %w", descriptionFilePath, err)
		}
		defer func() {
			if err := descriptionFile.Close(); err != nil {
				logger.Error(err, "Error closing description file", "path", descriptionFilePath)
			}
		}()

		return ldr.Load(descriptionFile)
	}

	if flags.Changed(descriptionFlagName) {
		description, err := flags.GetString(descriptionFlagName)
		if err != nil {
			return nil, fmt.Errorf("error retrieving %q flag: %w", descriptionFlagName, err)
		}

		return ldr.Load(strings.NewReader(description))
	}

	return ldr.Load(os.Stdin)
}
