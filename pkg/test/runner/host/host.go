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

package host

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/go-logr/logr"

	"github.com/falcosecurity/event-generator/pkg/baggage"
	"github.com/falcosecurity/event-generator/pkg/container"
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
	// processBuilder is the builder used to build a process.
	processBuilder process.Builder
	// containerBuilder is the builder used to build a container.
	containerBuilder container.Builder
	*runner.Description
}

// Verify that hostRunner implements runner.Runner interface.
var _ runner.Runner = (*hostRunner)(nil)

// New creates a new host runner.
func New(logger logr.Logger, testBuilder test.Builder, processBuilder process.Builder,
	containerBuilder container.Builder, description *runner.Description) (runner.Runner, error) {
	if testBuilder == nil {
		return nil, fmt.Errorf("test builder must not be nil")
	}

	if processBuilder == nil {
		return nil, fmt.Errorf("process builder must not be nil")
	}

	if containerBuilder == nil {
		return nil, fmt.Errorf("container builder must not be nil")
	}

	if description.TestDescriptionEnvKey == "" {
		return nil, fmt.Errorf("description.TestDescriptionEnvKey must not be empty")
	}

	if description.TestDescriptionFileEnvKey == "" {
		return nil, fmt.Errorf("description.TestDescriptionFileEnvKey must not be empty")
	}

	if description.TestDescriptionDirEnvKey == "" {
		return nil, fmt.Errorf("description.TestDescriptionDirEnvKey must not be empty")
	}

	if description.TestIDEnvKey == "" {
		return nil, fmt.Errorf("description.TestIDEnvKey must not be empty")
	}

	if description.TestIDIgnorePrefix == "" {
		return nil, fmt.Errorf("description.TestIDIgnorePrefix must not be empty")
	}

	if description.BaggageEnvKey == "" {
		return nil, fmt.Errorf("description.BaggageEnvKey must not be empty")
	}

	r := &hostRunner{
		logger:           logger,
		testBuilder:      testBuilder,
		processBuilder:   processBuilder,
		containerBuilder: containerBuilder,
		Description:      description,
	}
	return r, nil
}

func (r *hostRunner) Run(ctx context.Context, testID string, testDesc *loader.Test) error {
	testLogger := r.logger.WithName("test")

	if testContext := testDesc.Context; testContext != nil {
		delegated, err := r.setUpContext(ctx, testLogger.WithName("context"), testID, testDesc)
		if err != nil {
			return fmt.Errorf("error setting up the context: %w", err)
		}

		if delegated {
			return nil
		}
	}

	// Build test.
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

// setUpContext sets up the context specified in the provided test description. The function returns a boolean
// indicating if the test execution was delegated to a container/child process.
func (r *hostRunner) setUpContext(ctx context.Context, logger logr.Logger, testID string,
	testDesc *loader.Test) (delegated bool, err error) {
	testContext := testDesc.Context

	// Delegate to container if the user specified a container context.
	if testContext.Container != nil {
		logger := logger.WithName("container")
		if err := r.delegateToContainer(ctx, logger, testID, testDesc); err != nil {
			return false, fmt.Errorf("error delegating to container: %w", err)
		}

		return true, nil
	}

	// Delegate to child process if we are not at the end of the process chain.
	if len(testDesc.Context.Processes) != 0 {
		logger := logger.WithName("process")
		if err := r.delegateToProcess(ctx, logger, testID, testDesc); err != nil {
			return false, fmt.Errorf("error delegating to child process: %w", err)
		}

		return true, nil
	}

	return false, nil
}

// delegateToContainer delegates the execution of the test to a container, created and tuned as per test specification.
func (r *hostRunner) delegateToContainer(ctx context.Context, logger logr.Logger, testID string,
	testDesc *loader.Test) error {
	// Initialize baggage for the container's process.
	bag := r.Baggage
	bag.IsContainer = true
	bag.ProcIndex++

	containerContext := popContainer(testDesc.Context)

	// Configure the container.
	containerBuilder := r.containerBuilder

	containerBuilder.SetLogger(logger)

	if imageName := containerContext.Image; imageName != nil {
		containerBuilder.SetImageName(*imageName)
		bag.ContainerImageName = *imageName
	}

	if containerName := containerContext.Name; containerName != nil {
		containerBuilder.SetContainerName(*containerName)
		bag.ContainerName = *containerName
	}

	containerEnv, err := r.buildEnv(testID, containerContext.Env, testDesc, false, bag)
	if err != nil {
		return fmt.Errorf("error building container environment variables set: %w", err)
	}
	containerBuilder.SetEnv(containerEnv)

	cont := containerBuilder.Build()

	// Run the container and wait for it.
	if err := cont.Start(ctx); err != nil {
		return fmt.Errorf("error starting container: %w", err)
	}

	if err := cont.Wait(ctx); err != nil {
		return fmt.Errorf("error waiting for container: %w", err)
	}

	return nil
}

// popContainer removes and returns the container context from the provided testContext.
func popContainer(testContext *loader.TestContext) *loader.ContainerContext {
	containerContext := testContext.Container
	testContext.Container = nil
	return containerContext
}

// buildEnv builds the environment variable set for a given process, leveraging the provided test data and the
// additional user-provided environment variables and the baggage.
func (r *hostRunner) buildEnv(testID string, userEnv map[string]string, testDesc *loader.Test,
	isLastProcess bool, bag *baggage.Baggage) ([]string, error) {
	const additionalEnvVars = 3 // testID + description + baggage.
	env := make([]string, 0, len(userEnv)+len(r.Environ)+additionalEnvVars)

	// Add the test ID environment variable.
	if isLastProcess {
		testID = r.stripTestIDIgnorePrefix(testID)
	}
	env = append(env, buildEnvVar(r.TestIDEnvKey, testID))

	// Add the user-provided environment variables.
	for key, value := range userEnv {
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}

	// Add the test description environment variable building it from the serialized test description.
	description, err := marshalTestDescription(testDesc)
	if err != nil {
		return nil, fmt.Errorf("error serializing new test description: %w", err)
	}
	env = append(env, buildEnvVar(r.TestDescriptionEnvKey, description))

	// Add the baggage environment variable.
	baggageValue, err := marshalBaggage(bag)
	if err != nil {
		return nil, fmt.Errorf("error serializing baggage: %w", err)
	}
	env = append(env, buildEnvVar(r.BaggageEnvKey, baggageValue))

	// Add the process environment, but exclude the environment variables that we overrode.
	for _, envVar := range r.Environ {
		if envKey, _, found := strings.Cut(envVar, "="); !found || !r.mustOverrideEnv(envKey) {
			env = append(env, envVar)
		}
	}

	return env, nil
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

// buildEnvVar creates an environment variable string in the form "<envKey>=<envValue>".
func buildEnvVar(envKey, envValue string) string {
	return fmt.Sprintf("%s=%s", envKey, envValue)
}

// stripTestIDIgnorePrefix strips the ignore prefix from the provided test ID and returns it. The returned value is
// indeed the test UID.
func (r *hostRunner) stripTestIDIgnorePrefix(testID string) string {
	return strings.TrimPrefix(testID, r.TestIDIgnorePrefix)
}

// marshalBaggage returns the serialized baggage.
func marshalBaggage(bag *baggage.Baggage) (string, error) {
	sb := &strings.Builder{}
	if err := bag.Write(sb); err != nil {
		return "", err
	}

	return sb.String(), nil
}

// mustOverrideEnv returns true if the value associated to provided environment variable key is overridden by the runner
// upon run delegation.
func (r *hostRunner) mustOverrideEnv(key string) bool {
	switch key {
	case r.TestIDEnvKey, r.TestDescriptionEnvKey, r.BaggageEnvKey, r.TestDescriptionFileEnvKey, r.TestDescriptionDirEnvKey:
		return true
	default:
		return false
	}
}

// delegateToProcess delegates the execution of the test to a process, created and tuned as per test specification.
func (r *hostRunner) delegateToProcess(ctx context.Context, logger logr.Logger, testID string,
	testDesc *loader.Test) error {
	firstProcess := popFirstProcessContext(testDesc.Context)
	isLastProcess := len(testDesc.Context.Processes) == 0

	// Evaluate process environment variables.
	bag := r.Baggage
	bag.ProcIndex++

	procEnv, err := r.buildEnv(testID, firstProcess.Env, testDesc, isLastProcess, bag)
	if err != nil {
		return fmt.Errorf("error building process environment variables set: %w", err)
	}

	// Get current process executable path.
	currentExePath, err := getCurrentExePath()
	if err != nil {
		return fmt.Errorf("error retrieving the current process executable path: %w", err)
	}

	// Build child process using the collected information.
	if exePath := firstProcess.ExePath; exePath != nil {
		r.processBuilder.SetSimExePath(*exePath)
	}
	if name := firstProcess.Name; name != nil {
		r.processBuilder.SetName(*name)
	}
	if exe := firstProcess.Exe; exe != nil {
		r.processBuilder.SetArg0(*exe)
	}
	if args := firstProcess.Args; args != nil {
		r.processBuilder.SetArgs(*args)
	}
	if user := firstProcess.User; user != nil {
		r.processBuilder.SetUsername(*user)
	}
	if capabilities := firstProcess.Capabilities; capabilities != nil {
		r.processBuilder.SetCapabilities(*capabilities)
	}
	r.processBuilder.SetEnv(procEnv)
	proc := r.processBuilder.Build(ctx, logger, currentExePath)

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

// getCurrentExePath retrieves the current process executable path.
func getCurrentExePath() (string, error) {
	return os.Readlink(fmt.Sprintf("/proc/%d/exe", os.Getpid()))
}
