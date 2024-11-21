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

package host

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/go-logr/logr"

	"github.com/falcosecurity/event-generator/pkg/process"
	"github.com/falcosecurity/event-generator/pkg/test"
	"github.com/falcosecurity/event-generator/pkg/test/loader"
	"github.com/falcosecurity/event-generator/pkg/test/runner"
)

// hostRunner is an implementation of runner.Runner enabling test execution on the host system.
type hostRunner struct {
	// logger is the test runner logger.
	logger logr.Logger
	// testBuilder is the builder used to build a test.
	testBuilder test.Builder
	*runner.Description
}

// Verify that hostRunner implements runner.Runner interface.
var _ runner.Runner = (*hostRunner)(nil)

// New creates a new host runner.
func New(logger logr.Logger, testBuilder test.Builder, description *runner.Description) (runner.Runner, error) {
	if testBuilder == nil {
		return nil, fmt.Errorf("test builder must not be nil")
	}

	if description.TestDescriptionEnvKey == "" {
		return nil, fmt.Errorf("description.TestDescriptionEnvKey must not be empty")
	}

	if description.TestDescriptionFileEnvKey == "" {
		return nil, fmt.Errorf("description.TestDescriptionFileEnvKey must not be empty")
	}

	if description.TestIDEnvKey == "" {
		return nil, fmt.Errorf("description.TestIDEnvKey must not be empty")
	}

	if description.TestIDIgnorePrefix == "" {
		return nil, fmt.Errorf("description.TestIDIgnorePrefix must not be empty")
	}

	if description.ProcLabelEnvKey == "" {
		return nil, fmt.Errorf("description.ProcLabelEnvKey must not be empty")
	}

	r := &hostRunner{
		logger:      logger,
		testBuilder: testBuilder,
		Description: description,
	}
	return r, nil
}

func (r *hostRunner) Run(ctx context.Context, testID string, testIndex int, testDesc *loader.Test) error {
	// Delegate to child process if we are not at the end of the chain.
	if testDesc.Context != nil && len(testDesc.Context.Processes) != 0 {
		if err := r.delegateToChild(ctx, testID, testIndex, testDesc); err != nil {
			return fmt.Errorf("error delegating to child process: %w", err)
		}

		return nil
	}

	// Build test.
	testLogger := r.logger.WithName("test").WithValues("testUid", r.getTestUID(testID), "testName",
		testDesc.Name, "testIndex", testIndex)
	testInstance, err := r.testBuilder.Build(testLogger, testDesc)
	if err != nil {
		return fmt.Errorf("error building test: %w", err)
	}

	// Run test.
	if err := testInstance.Run(ctx); err != nil {
		return fmt.Errorf("error running test: %w", err)
	}

	return nil
}

// delegateToChild delegates the execution of the test to a child process, created and tuned as per test specification.
func (r *hostRunner) delegateToChild(ctx context.Context, testID string, testIndex int, testDesc *loader.Test) error {
	firstProcess := popFirstProcessContext(testDesc.Context)
	isLastProcess := len(testDesc.Context.Processes) == 0

	// Evaluate process environment variables.
	procEnv, err := r.buildEnv(testID, testIndex, testDesc, firstProcess.Env, isLastProcess)
	if err != nil {
		return fmt.Errorf("error building process environment variables set: %w", err)
	}

	// Get current process executable path.
	currentExePath, err := getCurrentExePath()
	if err != nil {
		return fmt.Errorf("error retrieving the current process executable path: %w", err)
	}

	var simExePath, name, arg0, args, username, capabilities string
	if firstProcess.ExePath != nil {
		simExePath = *firstProcess.ExePath
	}
	if firstProcess.Name != nil {
		name = *firstProcess.Name
	}
	if firstProcess.Exe != nil {
		arg0 = *firstProcess.Exe
	}
	if firstProcess.Args != nil {
		args = *firstProcess.Args
	}
	if firstProcess.User != nil {
		username = *firstProcess.User
	}
	if firstProcess.Capabilities != nil {
		capabilities = *firstProcess.Capabilities
	}
	procDesc := &process.Description{
		Logger:       r.logger.WithName("process"),
		Command:      currentExePath,
		SimExePath:   simExePath,
		Name:         name,
		Arg0:         arg0,
		Args:         args,
		Env:          procEnv,
		Username:     username,
		Capabilities: capabilities,
	}
	proc := process.New(ctx, procDesc)
	// Run the child process and wait for it.
	if err := proc.Start(); err != nil {
		return fmt.Errorf("error starting child process: %w", err)
	}

	if err := proc.Wait(); err != nil {
		return fmt.Errorf("error waiting for child process: %w", err)
	}

	return nil
}

// popFirstProcessContext removes and returns the first process context from the provided testContext.
func popFirstProcessContext(testContext *loader.TestContext) *loader.ProcessContext {
	processes := testContext.Processes
	firstProcess := processes[0]
	testContext.Processes = processes[1:]
	return &firstProcess
}

func (r *hostRunner) buildEnv(testID string, testIndex int, testDesc *loader.Test, userEnv map[string]string,
	isLastProcess bool) ([]string, error) {
	env := r.Environ

	// Add the user-provided environment variable.
	for key, value := range userEnv {
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}

	// Set test description environment variable to the serialized test description.
	description, err := marshalTestDescription(testDesc)
	if err != nil {
		return nil, fmt.Errorf("error serializing new test description: %w", err)
	}
	descriptionEnvVar := buildEnvVar(r.TestDescriptionEnvKey, description)

	// Set test ID environment variable.
	if isLastProcess {
		testID = r.getTestUID(testID)
	}
	testIDEnvVar := buildEnvVar(r.TestIDEnvKey, testID)

	// Set process label environment variable.
	procLabel, err := r.buildProcLabel(testIndex)
	if err != nil {
		return nil, fmt.Errorf("error building process label: %w", err)
	}
	procLabelEnvVar := buildEnvVar(r.ProcLabelEnvKey, procLabel)

	// Override test description file environment variable to avoid conflicts with the test description environment
	// variable.
	descriptionFileEnvVar := buildEnvVar(r.TestDescriptionFileEnvKey, "")

	env = append(env, descriptionEnvVar, testIDEnvVar, procLabelEnvVar, descriptionFileEnvVar)
	return env, nil
}

// buildEnvVar creates an environment variable string in the form "<envKey>=<envValue>".
func buildEnvVar(envKey, envValue string) string {
	return fmt.Sprintf("%s=%s", envKey, envValue)
}

// marshalTestDescription returns the serialized content of a test description object containing only the provided test.
func marshalTestDescription(testDesc *loader.Test) (string, error) {
	desc := &loader.Description{Tests: []loader.Test{*testDesc}}
	sb := &strings.Builder{}
	if err := desc.Write(sb); err != nil {
		return "", err
	}

	return sb.String(), nil
}

// getTestUID extracts the test UID from the test ID by removing the ignore prefix.
func (r *hostRunner) getTestUID(testID string) string {
	return strings.TrimPrefix(testID, r.TestIDIgnorePrefix)
}

// buildProcLabel builds a process label. If the current process Label is not defined, it uses the provided testIndex to
// create a new one; otherwise, given the process label in the form testName,child<childIndex>, it returns
// testName,child<childIndex+1>.
func (r *hostRunner) buildProcLabel(testIndex int) (string, error) {
	procLabel := r.ProcLabel
	if procLabel == "" {
		return fmt.Sprintf("test%d,child0", testIndex), nil
	}

	labelParts := strings.Split(procLabel, ",")
	if len(labelParts) != 2 {
		return "", fmt.Errorf("cannot parse process label")
	}

	testName, procName := labelParts[0], labelParts[1]
	childIndex, err := strconv.Atoi(strings.TrimPrefix(procName, "child"))
	if err != nil {
		return "", fmt.Errorf("error parsing process name in process label %q: %w", procName, err)
	}

	return fmt.Sprintf("%s,child%d", testName, childIndex+1), nil
}

// getCurrentExePath retrieves the current process executable path.
func getCurrentExePath() (string, error) {
	return os.Readlink(fmt.Sprintf("/proc/%d/exe", os.Getpid()))
}
