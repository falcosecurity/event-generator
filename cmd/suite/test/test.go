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

package test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/thediveo/enumflag"

	"github.com/falcosecurity/event-generator/cmd/internal/alertretriever"
	"github.com/falcosecurity/event-generator/cmd/suite/config"
	"github.com/falcosecurity/event-generator/pkg/baggage"
	containerbuilder "github.com/falcosecurity/event-generator/pkg/container/builder"
	processbuilder "github.com/falcosecurity/event-generator/pkg/process/builder"
	"github.com/falcosecurity/event-generator/pkg/test"
	testbuilder "github.com/falcosecurity/event-generator/pkg/test/builder"
	"github.com/falcosecurity/event-generator/pkg/test/loader"
	resbuilder "github.com/falcosecurity/event-generator/pkg/test/resource/builder"
	"github.com/falcosecurity/event-generator/pkg/test/runner"
	runnerbuilder "github.com/falcosecurity/event-generator/pkg/test/runner/builder"
	stepbuilder "github.com/falcosecurity/event-generator/pkg/test/step/builder"
	sysbuilder "github.com/falcosecurity/event-generator/pkg/test/step/syscall/builder"
	"github.com/falcosecurity/event-generator/pkg/test/suite"
	suiteloader "github.com/falcosecurity/event-generator/pkg/test/suite/loader"
	"github.com/falcosecurity/event-generator/pkg/test/suite/reportencoder/jsonencoder"
	"github.com/falcosecurity/event-generator/pkg/test/suite/reportencoder/textencoder"
	"github.com/falcosecurity/event-generator/pkg/test/suite/reportencoder/yamlencoder"
	suitesource "github.com/falcosecurity/event-generator/pkg/test/suite/source"
	"github.com/falcosecurity/event-generator/pkg/test/tester"
	testerimpl "github.com/falcosecurity/event-generator/pkg/test/tester/tester"
)

const (
	// testIDIgnorePrefix is the prefix used to mark a process as not monitored.
	testIDIgnorePrefix = "ignore:"
)

const (
	longDescriptionPrefaceTemplate = `%s.
It is possible to provide the YAML description in multiple ways. The order of evaluation is the following:
1) If --%s=<file_path> and/or --%s=<dir_path> flags are/is provided, the description is read from the file at <file_path>
2) If the --%s=<description> flag is provided, the description is read from the <description> string
3) Otherwise, it is read from standard input`
	longDescriptionHeading = "Run test(s) specified via a YAML description and verify that they produce the expected outcomes"
	warningMessage         = `Warning:
  This command might alter your system. For example, some actions modify files and directories below /bin, /etc, /dev,
  etc... Make sure you fully understand what is the purpose of this tool before running any action.`
)

var (
	longDescriptionPreface = fmt.Sprintf(longDescriptionPrefaceTemplate, longDescriptionHeading,
		config.DescriptionFileFlagName, config.DescriptionDirFlagName, config.DescriptionFlagName)
	longDescription = fmt.Sprintf("%s\n\n%s", longDescriptionPreface, warningMessage)
)

// reportFormat defines the types of format used for outputting a suite report.
type reportFormat int

const (
	// reportFormatText specifies to format a suite report using a formatted text encoding.
	reportFormatText reportFormat = iota
	// reportFormatJSON specifies to format a suite report using a JSON encoding.
	reportFormatJSON
	// reportFormatYAML specifies to format a suite report using a YAML encoding.
	reportFormatYAML
)

var reportFormats = map[reportFormat][]string{
	reportFormatText: {"text"},
	reportFormatJSON: {"json"},
	reportFormatYAML: {"yaml"},
}

// CommandWrapper is a wrapper around the test command storing the flag values bound to the command at runtime.
type CommandWrapper struct {
	*config.Config
	Command                 *cobra.Command
	skipOutcomeVerification bool
	AlertRetrieverConfig    alertretriever.Config
	reportFormat            reportFormat
}

// New creates a new test command.
func New(commonConf *config.Config, skipOutcomesVerification bool) *CommandWrapper {
	cw := &CommandWrapper{Config: commonConf, skipOutcomeVerification: skipOutcomesVerification}

	c := &cobra.Command{
		Use:               "test",
		Short:             longDescriptionHeading,
		Long:              longDescription,
		DisableAutoGenTag: true,
		Run:               cw.run,
	}

	cw.initFlags(c)

	cw.Command = c
	return cw
}

// initFlags initializes the provided command's flags.
func (cw *CommandWrapper) initFlags(c *cobra.Command) {
	// Initialize command's flags with the ones exported by the config.
	cw.Config.InitCommandFlags(c)

	// The following flags are all associated with outcome verification, so early return if we are going to skip that
	// step.
	if cw.skipOutcomeVerification {
		return
	}

	flags := c.Flags()

	flags.BoolVar(&cw.skipOutcomeVerification, "skip-outcome-verification", false,
		"Skip verification of the expected outcome. If this option is enabled, http- flags are ignored")
	cw.AlertRetrieverConfig.InitCommandFlags(c)
	flags.Var(
		enumflag.New(&cw.reportFormat, "report-format", reportFormats, enumflag.EnumCaseInsensitive),
		"report-format", "The format of the test suites report; can be 'text', 'json' or 'yaml'")
}

// envKeyFromFlagName converts the provided flag name into the corresponding environment variable key.
func envKeyFromFlagName(envKeysPrefix, flagName string) string {
	s := fmt.Sprintf("%s_%s", envKeysPrefix, strings.ToUpper(flagName))
	s = strings.ToUpper(s)
	return strings.ReplaceAll(s, "-", "_")
}

// run runs the provided command with the provided arguments.
func (cw *CommandWrapper) run(cmd *cobra.Command, _ []string) {
	ctx := cmd.Context()
	logger, err := logr.FromContext(ctx)
	if err != nil {
		panic(fmt.Sprintf("logger unconfigured: %v", err))
	}

	logger = logger.WithName("main")

	ctx, cancel := context.WithTimeout(ctx, cw.TestsTimeout)
	defer cancel()
	abort := func() {
		cancel()
		os.Exit(1)
	}

	baseBag, err := baggage.NewFromString(cw.Baggage)
	if err != nil {
		logger.Error(err, "Error parsing baggage")
		abort()
	}

	logger = enrichLoggerWithBaggage(logger, baseBag)

	// The test ID absence is used to uniquely identify the root process in the process chain.
	isRootProcess := cw.TestID == ""
	verifyExpectedOutcome := isRootProcess && !cw.skipOutcomeVerification

	testSuites, err := loadTestSuites(logger, !verifyExpectedOutcome, cw.TestsDescriptionFiles, cw.TestsDescriptionDirs,
		cw.TestsDescription)
	if err != nil {
		if noRuleNameErr := (*suite.NoRuleNameError)(nil); errors.As(err, &noRuleNameErr) {
			logger = logger.WithValues("testName", noRuleNameErr.TestName, "testSourceName",
				noRuleNameErr.TestSourceName, "testSourceIndex", noRuleNameErr.TestSourceIndex)
		}
		logger.Error(err, "Error loading test suites")
		abort()
	}

	runnerBuilder, err := cw.createRunnerBuilder()
	if err != nil {
		logger.Error(err, "Error creating runner builder")
		abort()
	}

	// The following variables and functions are set/initialized with meaningful values only in the context of the root
	// process if the user requested to verify the test outcomes.

	// Tester for collecting Falco alerts and generating reports.
	var testr tester.Tester
	// Wait group for accounting all goroutines collecting or processing reports.
	var waitGroup sync.WaitGroup
	// Channel where test reports are produced.
	reportCh := make(chan *tester.Report)
	// Channel that is closed when all reports have been collected.
	reportCollectionCompletedCh := make(chan struct{})
	// Function ensuring an empty report is sent whenever a panic or failure condition occur
	sendEmptyTestReportIfPanicOrFailure := func(_ /*testSuiteName*/, _ /*testName*/ string,
		_ /*originatingTestCase*/ loader.TestCase, _ /*failCond*/ *bool) {
	} // noop
	// Function for scheduling report production
	scheduleReportProduction := func(_ /*testUID*/ *uuid.UUID, _ /*testDesc*/ *loader.Test) {} // noop

	if verifyExpectedOutcome {
		// Initialize tester.
		if testr, err = cw.createTester(logger); err != nil {
			logger.Error(err, "Error creating tester")
			abort()
		}

		// Schedule tester Falco alerts collection.
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			defer cancel()
			if err := testr.StartAlertsCollection(ctx); err != nil {
				logger.Error(err, "Error starting tester execution")
			}
		}()

		// Schedule test suites reports collection and printing.
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			defer close(reportCollectionCompletedCh)
			defer close(reportCh)
			expectedReportsNum := getTestsNum(testSuites)
			testSuitesReports, err := collectTestSuitesReports(ctx, expectedReportsNum, reportCh)
			if err != nil {
				return
			}
			cw.printTestSuitesReports(testSuitesReports)
		}()

		sendEmptyTestReportIfPanicOrFailure = func(testSuiteName, testName string, originatingTestCase loader.TestCase,
			failCond *bool) {
			if ctx.Err() != nil {
				return
			}
			if v := recover(); v != nil || *failCond {
				logger.Error(fmt.Errorf("%v", v), "Sent empty report due to unexpected error or failure",
					"testSuiteName", testSuiteName, "testName", testName, "testCase",
					formatTestCase(originatingTestCase))
				emptyReport := &tester.Report{
					RuleName:            testSuiteName,
					TestName:            testName,
					OriginatingTestCase: originatingTestCase,
				}
				sendTestReport(ctx, reportCh, emptyReport)
			}
		}

		scheduleReportProduction = func(testUID *uuid.UUID, testDesc *loader.Test) {
			waitGroup.Add(1)
			go func() {
				defer waitGroup.Done()
				notFailed := false
				defer sendEmptyTestReportIfPanicOrFailure(*testDesc.Rule, testDesc.Name, testDesc.OriginatingTestCase,
					&notFailed)
				produceTestReport(ctx, testr, testUID, testDesc, reportCh)
			}()
		}
	} else {
		// These channels are not used in this case, so close them.
		close(reportCollectionCompletedCh)
		close(reportCh)
	}

	// Prepare parameters shared by all runners.
	runnerEnviron := cw.buildRunnerEnviron(cmd)

	// Run test suites.
	baseLogger := logger
	for _, testSuite := range testSuites {
		testSuiteName := testSuite.RuleName
		logger := baseLogger.WithValues("testSuiteName", testSuiteName)
		logInfoIf(logger, isRootProcess, "Starting test suite execution...")
		// Run all tests in the test suite.
		for _, testInfo := range testSuite.TestsInfo {
			// Wrap execution in a function to allow deferring sendEmptyTestReportIfPanicOrFailure.
			func() {
				testExecutionFailed := false
				defer sendEmptyTestReportIfPanicOrFailure(testSuiteName, testInfo.Test.Name,
					testInfo.Test.OriginatingTestCase, &testExecutionFailed)

				// Run the test.
				if testExecutionFailed = cw.runTest(ctx, baseLogger, testSuiteName, testInfo, runnerBuilder,
					runnerEnviron, baseBag, isRootProcess, scheduleReportProduction); !testExecutionFailed {
					return
				}

				// Test execution failed. Abort execution if this is not the root process of the context was canceled.
				if !isRootProcess || ctx.Err() != nil {
					cancel()
					waitGroup.Wait()
					os.Exit(1)
				}
			}()
		}
		logInfoIf(logger, isRootProcess, "Test suite execution completed")
	}

	<-reportCollectionCompletedCh
	cancel()
	waitGroup.Wait()
}

// enrichLoggerWithBaggage creates a new logger, starting from the provided one, with the information extracted from the
// provided baggage.
func enrichLoggerWithBaggage(logger logr.Logger, bag *baggage.Baggage) logr.Logger {
	if bag == nil {
		return logger
	}

	logger = logger.WithValues("testSuiteName", bag.TestSuiteName, "testName", bag.TestName, "testSourceName",
		bag.TestSourceName, "testSourceIndex", bag.TestSourceIndex)
	if bag.TestCase != nil {
		logger = logger.WithValues("testCase", formatTestCase(bag.TestCase))
	}
	if bag.ProcIndex != -1 {
		logger = logger.WithValues("procIndex", bag.ProcIndex)
	}
	if bag.IsContainer {
		logger = logger.WithValues("inContainer", bag.IsContainer)
		if imageName := bag.ContainerImageName; imageName != "" {
			logger = logger.WithValues("containerImageName", imageName)
		}
		if containerName := bag.ContainerName; containerName != "" {
			logger = logger.WithValues("containerName", containerName)
		}
	}
	return logger
}

// formatTestCase returns a formatted version of the provided test case.
func formatTestCase(testCase loader.TestCase) string {
	var s string
	for k, v := range testCase {
		s += fmt.Sprintf("%s=%v,", k, v)
	}
	if s != "" {
		s = s[:len(s)-1]
	}
	return s
}

// loadTestSuites loads the test suites from a different source, depending on the content of the provided values:
//   - if the provided descriptionFilePaths or descriptionDirPaths are not empty, the test suites are loaded both from
//     the specified files (if any) and from the YAML files (if any) in the specified directories (if any);
//   - if the provided description is not empty, the test suites are loaded from its content;
//   - otherwise, they are loaded from standard input.
//
// The parameter canLoadTestsWithNoRuleName is used to allow/disallow loading of tests with absent or empty rule names.
func loadTestSuites(logger logr.Logger, canLoadTestsWithNoRuleName bool, descriptionFilePaths,
	descriptionDirPaths []string, description string) ([]*suite.Suite, error) {
	descLoader := loader.New()
	testSuiteLoader := suiteloader.New(descLoader, canLoadTestsWithNoRuleName)

	// Load from the specified files or directories.
	if len(descriptionFilePaths) > 0 || len(descriptionDirPaths) > 0 {
		for _, descriptionDirPath := range descriptionDirPaths {
			if err := loadTestsFromDescriptionDir(logger, testSuiteLoader, descriptionDirPath); err != nil {
				return nil, fmt.Errorf("error loading description directory %q: %w", descriptionDirPath, err)
			}
		}

		for _, descriptionFilePath := range descriptionFilePaths {
			if err := loadTestsFromDescriptionFile(logger, testSuiteLoader, descriptionFilePath); err != nil {
				return nil, fmt.Errorf("error loading description file %q: %w", descriptionFilePath, err)
			}
		}

		return testSuiteLoader.Get(), nil
	}

	// Load from the provided description string.
	if description != "" {
		source := suitesource.New("<description flag>", strings.NewReader(description))
		if err := testSuiteLoader.Load(source); err != nil {
			return nil, fmt.Errorf("error loading from description flag: %w", err)
		}
		return testSuiteLoader.Get(), nil
	}

	// Load from standard input.
	source := suitesource.New("<stdin>", os.Stdin)
	if err := testSuiteLoader.Load(source); err != nil {
		return nil, fmt.Errorf("error loading from stdin: %w", err)
	}
	return testSuiteLoader.Get(), nil
}

// loadTestsFromDescriptionDir loads tests, from YAML files inside the directory at the provided path, into the provided
// suite loader.
func loadTestsFromDescriptionDir(logger logr.Logger, testSuiteLoader suite.Loader, descriptionDirPath string) error {
	descriptionDirPath = filepath.Clean(descriptionDirPath)
	dirEntries, err := os.ReadDir(descriptionDirPath)
	if err != nil {
		return fmt.Errorf("error reading entries in directory %q: %w", descriptionDirPath, err)
	}

	for _, dirEntry := range dirEntries {
		if dirEntry.IsDir() {
			continue
		}

		name := dirEntry.Name()
		if !strings.HasSuffix(name, ".yaml") {
			continue
		}

		descriptionFilePath := filepath.Join(descriptionDirPath, name)
		if err := loadTestsFromDescriptionFile(logger, testSuiteLoader, descriptionFilePath); err != nil {
			return fmt.Errorf("error loading description file %q: %w", name, err)
		}
	}

	return nil
}

// loadTestsFromDescriptionFile loads tests from the file at the provided path into the provided suite loader.
func loadTestsFromDescriptionFile(logger logr.Logger, testSuiteLoader suite.Loader, descriptionFilePath string) error {
	descriptionFilePath = filepath.Clean(descriptionFilePath)
	descriptionFile, err := os.Open(descriptionFilePath)
	if err != nil {
		return fmt.Errorf("error opening file path %q: %w", descriptionFilePath, err)
	}
	defer func() {
		if err := descriptionFile.Close(); err != nil {
			logger.Error(err, "Error closing description file", "path", descriptionFilePath)
		}
	}()

	return testSuiteLoader.Load(descriptionFile)
}

// createRunnerBuilder creates a new runner builder.
func (cw *CommandWrapper) createRunnerBuilder() (runner.Builder, error) {
	resourceProcessBuilder := processbuilder.New()
	resourceBuilder, err := resbuilder.New(resourceProcessBuilder)
	if err != nil {
		return nil, fmt.Errorf("error creating resource builder: %w", err)
	}

	syscallBuilder := sysbuilder.New()
	stepBuilder, err := stepbuilder.New(syscallBuilder)
	if err != nil {
		return nil, fmt.Errorf("error creating step builder: %w", err)
	}

	testBuilder, err := testbuilder.New(resourceBuilder, stepBuilder)
	if err != nil {
		return nil, fmt.Errorf("error creating test builder: %w", err)
	}

	runnerProcessBuilder := processbuilder.New()

	runnerContainerBuilderOptions := []containerbuilder.Option{
		containerbuilder.WithUnixSocketURL(cw.ContainerRuntimeUnixSocketURL),
		containerbuilder.WithBaseImageName(cw.ContainerBaseImageName),
		containerbuilder.WithBaseImagePullPolicy(cw.ContainerImagePullPolicy),
	}
	runnerContainerBuilder, err := containerbuilder.New(runnerContainerBuilderOptions...)
	if err != nil {
		return nil, fmt.Errorf("error creating container builder: %w", err)
	}

	return runnerbuilder.New(testBuilder, runnerProcessBuilder, runnerContainerBuilder)
}

// createTester creates a new tester.
func (cw *CommandWrapper) createTester(logger logr.Logger) (tester.Tester, error) {
	httpRetriever, err := cw.AlertRetrieverConfig.Build(logger.WithName("alert-retriever"))
	if err != nil {
		return nil, fmt.Errorf("error creating HTTP retriever: %w", err)
	}

	t := testerimpl.New(httpRetriever, cw.TestIDEnvKey, testIDIgnorePrefix)
	return t, nil
}

// getTestsNum returns the total number of tests contained in the provided test suites.
func getTestsNum(testSuites []*suite.Suite) int {
	count := 0
	for _, testSuite := range testSuites {
		count += len(testSuite.TestsInfo)
	}
	return count
}

// collectTestSuitesReports collects test reports for all test suites from the provided report channel and returns a
// map associating to each test suite name the list of test reports. The collection ends after expectedReportsNum are
// received or the context is canceled.
// Notice: the assumption here is that we expect to receive exactly one report for each test.
func collectTestSuitesReports(ctx context.Context, expectedReportsNum int,
	reportCh <-chan *tester.Report) (map[string][]*tester.Report, error) {
	testSuitesReports := make(map[string][]*tester.Report)
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case report := <-reportCh:
			testSuiteName := report.RuleName
			testSuitesReports[testSuiteName] = append(testSuitesReports[testSuiteName], report)
			expectedReportsNum--
			if expectedReportsNum == 0 {
				return testSuitesReports, nil
			}
		}
	}
}

// printTestSuitesReports prints tests reports for the provided tests suites.
func (cw *CommandWrapper) printTestSuitesReports(testSuitesReports map[string][]*tester.Report) {
	suiteReportEncoder := newTestSuiteReportEncoder(cw.reportFormat)
	for testSuiteName, testSuiteReports := range testSuitesReports {
		testSuiteReport := &suite.Report{
			TestSuiteName: testSuiteName,
			TestReports:   testSuiteReports,
		}
		// TODO: perform error checking
		_ = suiteReportEncoder.Encode(testSuiteReport)
	}
}

// newTestSuiteReportEncoder creates a new test suite report encoder corresponding to the provided format.
func newTestSuiteReportEncoder(reportFmt reportFormat) suite.ReportEncoder {
	var encoder suite.ReportEncoder
	switch reportFmt {
	case reportFormatText:
		encoder = textencoder.New(os.Stdout)
	case reportFormatJSON:
		encoder = jsonencoder.New(os.Stdout)
	case reportFormatYAML:
		encoder = yamlencoder.New(os.Stdout)
	default:
		panic(fmt.Sprintf("unsupported report format %v", reportFmt))
	}
	return encoder
}

// sendTestReport sends the provided report to the provided channel or cancel the operation if the provided context is
// canceled before the aforementioned operation succeeds.
func sendTestReport(ctx context.Context, reportCh chan<- *tester.Report, report *tester.Report) {
	select {
	case <-ctx.Done():
	case reportCh <- report:
	}
}

// buildRunnerEnviron creates a list of strings representing the environment, by adding to the current process
// environment all the provided command flags and all the required environment variable needed to enable the runner to
// rerun the current executable with the proper environment configuration.
func (cw *CommandWrapper) buildRunnerEnviron(cmd *cobra.Command) []string {
	environ := os.Environ()
	environ = cw.appendFlags(environ, cmd.PersistentFlags(), cmd.Flags())
	environ = append(environ, fmt.Sprintf("%s=1", cw.SuiteEnvKey))
	return environ
}

// appendFlags appends the provided flag sets' flags to environ and returns the updated environ. Works like the builtin
// append function.
func (cw *CommandWrapper) appendFlags(environ []string, flagSets ...*pflag.FlagSet) []string {
	appendFlag := func(flag *pflag.Flag) {
		keyName := envKeyFromFlagName(cw.EnvKeysPrefix, flag.Name)
		environ = append(environ, fmt.Sprintf("%s=%s", keyName, flag.Value.String()))
	}
	for _, flagSet := range flagSets {
		flagSet.VisitAll(appendFlag)
	}
	return environ
}

// logInfoIf outputs to the provided logger the provided informational message only if the provided condition is true.
func logInfoIf(logger logr.Logger, cond bool, msg string) {
	if cond {
		logger.Info(msg)
	}
}

// runTest runs the provided test and returns a boolean indicating if the test execution failed or not.
// TODO: simplify the following function signature once the termination logic is relaxed.
func (cw *CommandWrapper) runTest(ctx context.Context, logger logr.Logger, testSuiteName string,
	testInfo *suite.TestInfo, runnerBuilder runner.Builder, runnerEnviron []string, baseBag *baggage.Baggage,
	isRootProcess bool, scheduleReportProduction func(testUID *uuid.UUID, testDesc *loader.Test)) bool {
	// Init baggage and logger for the current test.
	var bag *baggage.Baggage
	if baseBag != nil {
		bag = baseBag.Clone()
	}

	testSourceName, testDesc := testInfo.SourceName, testInfo.Test
	testSourceIndex, testCase := testDesc.SourceIndex, testDesc.OriginatingTestCase

	testID := cw.TestID
	var testUID uuid.UUID
	if isRootProcess {
		// The root process must initialize the baggage.
		bag = &baggage.Baggage{
			TestSuiteName:   testSuiteName,
			TestName:        testDesc.Name,
			TestSourceName:  testSourceName,
			TestSourceIndex: testSourceIndex,
			TestCase:        testCase,
			// ProcIndex is set to -1 on the root process.
			ProcIndex: -1,
		}
		logger = enrichLoggerWithBaggage(logger, bag)

		// Generate a new UID for the test.
		testUID = uuid.New()
		testID = newTestID(&testUID)
		ensureProcessChainLeaf(testDesc)
	} else {
		// Extract UID from test ID.
		var err error
		testUID, err = extractTestUID(testID)
		if err != nil {
			logger.Error(err, "Error extracting test UID from test ID", "testId", testID)
			return true
		}
	}

	logger = logger.WithValues("testUid", testUID)

	runnerLogger := logger.WithName("runner")
	runnerDescription := &runner.Description{
		Environ:                   runnerEnviron,
		TestDescriptionEnvKey:     cw.DescriptionEnvKey,
		TestDescriptionFileEnvKey: cw.DescriptionFileEnvKey,
		TestDescriptionDirEnvKey:  cw.DescriptionDirEnvKey,
		TestIDEnvKey:              cw.TestIDEnvKey,
		TestIDIgnorePrefix:        testIDIgnorePrefix,
		BaggageEnvKey:             cw.BaggageEnvKey,
		Baggage:                   bag,
	}
	runnerInstance, err := runnerBuilder.Build(testDesc.Runner, runnerLogger, runnerDescription)
	if err != nil {
		logger.Error(err, "Error creating runner")
		return true
	}

	logInfoIf(logger, isRootProcess, "Starting test execution...")
	if err := runnerInstance.Run(ctx, testID, testDesc); err != nil {
		logRunnerError(logger, err)
		return true
	}

	logInfoIf(logger, isRootProcess, "Test execution completed")

	scheduleReportProduction(&testUID, testDesc)
	return false
}

// newTestID creates a new test ID from the provided test UID.
func newTestID(uid *uuid.UUID) string {
	return fmt.Sprintf("%s%s", testIDIgnorePrefix, uid.String())
}

// ensureProcessChainLeaf ensures the process chain has at least one element. If the user didn't specify anything, add a
// default process to the chain.
func ensureProcessChainLeaf(testDesc *loader.Test) {
	if testDesc.Context == nil {
		testDesc.Context = &loader.TestContext{}
	}
	if len(testDesc.Context.Processes) == 0 && testDesc.Context.Container == nil {
		testDesc.Context.Processes = []loader.ProcessContext{{}}
	}
}

// extractTestUID extracts the test UID from the provided test ID.
func extractTestUID(testID string) (uuid.UUID, error) {
	return uuid.Parse(strings.TrimPrefix(testID, testIDIgnorePrefix))
}

// logRunnerError logs the provided runner error using the provided logger.
func logRunnerError(logger logr.Logger, err error) {
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
}

// produceTestReport tries, for a fixed maximum number of attempts, to produce a non-empty report for the given test by
// using the provided tester. The obtained non-empty report or an empty one (in the case the maximum number of attempts
// is reached), is produced in the provided report channel.
func produceTestReport(ctx context.Context, testr tester.Tester, testUID *uuid.UUID, testDesc *loader.Test,
	reportCh chan<- *tester.Report) {
	t := time.NewTimer(0)
	defer t.Stop()
	testName, ruleName, originatingTestCase := testDesc.Name, *testDesc.Rule, testDesc.OriginatingTestCase
	expectedOutcome := testDesc.ExpectedOutcome
	const maxAttempts = 4
	remainingAttempts := maxAttempts
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			report := testr.Report(testUID, ruleName, expectedOutcome)
			remainingAttempts--
			if !report.Empty() || remainingAttempts == 0 {
				report.TestName, report.RuleName, report.OriginatingTestCase = testName, ruleName, originatingTestCase
				sendTestReport(ctx, reportCh, report)
				return
			}

			if ctx.Err() == nil {
				t.Reset((1 << (maxAttempts - 1 - remainingAttempts)) * time.Second)
			}
		}
	}
}
