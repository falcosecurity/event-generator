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
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-logr/logr"

	"github.com/falcosecurity/event-generator/pkg/test"
	"github.com/falcosecurity/event-generator/pkg/test/loader"
	"github.com/falcosecurity/event-generator/pkg/test/runner"
)

// hostRunner is an implementation of runner.Runner enabling test execution on the host system.
type hostRunner struct {
	// logger is the test runner logger.
	logger logr.Logger
	// environ is a list of strings representing the environment, in the form "key=value".
	environ []string
	// testBuilder is the builder used to build a test.
	testBuilder test.Builder
	// testDescriptionEnvKey is the key identifying the environment variable used to store the serialized test
	// description.
	testDescriptionEnvKey string
	// testDescriptionFileEnvKey is the key identifying the environment variable used to store path of the file
	// containing the serialized test description.
	testDescriptionFileEnvKey string
	// procIDEnvKey is the key identifying the environment variable used to store the process identifier in the form
	// "test<testIndex>,child<childIndex>".
	procIDEnvKey string
	// procID is the current process ID.
	procID string
}

// Verify that hostRunner implements runner.Runner interface.
var _ runner.Runner = (*hostRunner)(nil)

// New creates a new host runner.
func New(logger logr.Logger, testBuilder test.Builder, environ []string, testDescriptionEnvKey,
	testDescriptionFileEnvKey, procIDEnvKey, procID string) (runner.Runner, error) {
	if testBuilder == nil {
		return nil, fmt.Errorf("test builder must not be nil")
	}

	if testDescriptionEnvKey == "" {
		return nil, fmt.Errorf("testDescriptionEnvKey must not be empty")
	}

	if procIDEnvKey == "" {
		return nil, fmt.Errorf("procIDEnvKey must not be empty")
	}

	r := &hostRunner{
		logger:                    logger,
		testBuilder:               testBuilder,
		environ:                   environ,
		testDescriptionEnvKey:     testDescriptionEnvKey,
		testDescriptionFileEnvKey: testDescriptionFileEnvKey,
		procIDEnvKey:              procIDEnvKey,
		procID:                    procID,
	}
	return r, nil
}

func (r *hostRunner) Run(ctx context.Context, testIndex int, testDesc *loader.Test) error {
	// Delegate to child process if we are not at the end of the chain.
	if testDesc.Context != nil && len(testDesc.Context.Processes) != 0 {
		if err := r.delegateToChild(ctx, testIndex, testDesc); err != nil {
			return fmt.Errorf("error delegating to child process: %w", err)
		}

		return nil
	}

	// Build test.
	testLogger := r.logger.WithName("test").WithValues("testName", testDesc.Name,
		"testIndex", testIndex)
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
func (r *hostRunner) delegateToChild(ctx context.Context, testIndex int, testDesc *loader.Test) error {
	firstProcess := popFirstProcessContext(testDesc.Context)

	realExePath := firstProcess.ExePath

	// If the user provides a process name, we must run the executable through a symbolic link having the provided name
	// and pointing to the real executable path.
	exePath := realExePath
	if name := firstProcess.Name; name != nil {
		exePath = filepath.Join(filepath.Dir(realExePath), *name)
	}

	// If the user provides the "exe" field, set the argument 0 of the new process to its value; otherwise defaults it
	// to the last segment of the executable path.
	arg0 := filepath.Base(exePath)
	if exe := firstProcess.Exe; exe != nil {
		arg0 = *exe
	}

	// Evaluate process arguments.
	procArgs := splitArgs(firstProcess.Args)

	// Evaluate process environment variables.
	procEnv, err := r.buildEnv(testIndex, testDesc, firstProcess.Env)
	if err != nil {
		return fmt.Errorf("error building process environment variables set: %w", err)
	}

	// Setup process command.
	cmd := exec.CommandContext(ctx, exePath, procArgs...) //nolint:gosec // Disable G204
	cmd.Args[0] = arg0
	cmd.Env = procEnv
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Create a hard link to the current process executable as specified by the user in the "ExePath" field.
	currentExePath, err := getCurrentExePath()
	if err != nil {
		return fmt.Errorf("error retrieving the current process executable path: %w", err)
	}

	if err := os.Link(currentExePath, realExePath); err != nil {
		return fmt.Errorf("error creating process executable: %w", err)
	}
	defer func() {
		if err := os.Remove(realExePath); err != nil {
			r.logger.Error(err, "Error deleting process executable", "path", realExePath)
		}
	}()

	// If the user specified a custom process name, we will run the executable through a symbolic link, so create it.
	if realExePath != exePath {
		if err := os.Symlink(realExePath, exePath); err != nil {
			return fmt.Errorf("error creating symlink %q to process executable %q: %w", exePath, realExePath,
				err)
		}
		defer func() {
			if err := os.Remove(exePath); err != nil {
				r.logger.Error(err, "Error deleting symlink to process executable", "symlink", exePath)
			}
		}()
	}

	// Run the child process and wait for it.
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("error starting child process: %w", err)
	}

	if err := cmd.Wait(); err != nil {
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

// splittingArgsRegex allows to split space-separated arguments, keeping together space-separated words under the same
// single- or double-quoted group.
var splittingArgsRegex = regexp.MustCompile(`"([^"]+)"|'([^']+)'|(\S+)`)

// splitArgs splits the provided space-separated arguments. If a group composed of space-separated words must be
// considered as a single argument, it must be single- or double-quoted.
func splitArgs(args *string) []string {
	if args == nil {
		return nil
	}

	matches := splittingArgsRegex.FindAllStringSubmatch(*args, -1)
	splittedArgs := make([]string, len(matches))
	for matchIndex, match := range matches {
		// match[1] is for double quotes, match[2] for single quotes, match[3] for unquoted.
		if match[1] != "" { //nolint:gocritic // Rewrite this as switch statement worsens readability.
			splittedArgs[matchIndex] = match[1]
		} else if match[2] != "" {
			splittedArgs[matchIndex] = match[2]
		} else if match[3] != "" {
			splittedArgs[matchIndex] = match[3]
		}
	}
	return splittedArgs
}

func (r *hostRunner) buildEnv(testIndex int, testDesc *loader.Test, userEnv map[string]string) ([]string, error) {
	// Use the current process environment variable as base.
	env := r.environ

	// Add the user-provided environment variable.
	for key, value := range userEnv {
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}

	// Set test description environment variable to the serialized test description.
	description, err := marshalTestDescription(testDesc)
	if err != nil {
		return nil, fmt.Errorf("error serializing new test description: %w", err)
	}
	descriptionEnvVar := buildEnvVar(r.testDescriptionEnvKey, description)

	// Set process ID environment variable.
	procID, err := r.buildProcID(testIndex)
	if err != nil {
		return nil, fmt.Errorf("error building process ID: %w", err)
	}
	procIDEnvVar := buildEnvVar(r.procIDEnvKey, procID)

	// Override test description file environment variable to avoid conflicts with the test description environment
	// variable
	descriptionFileEnvVar := buildEnvVar(r.testDescriptionFileEnvKey, "")

	env = append(env, descriptionEnvVar, procIDEnvVar, descriptionFileEnvVar)
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

// buildProcID builds a process ID. If the current process ID is not defined, it uses the provided testIndex to create a
// new one; otherwise, given the process ID in the form testName,child<childIndex>, it returns
// testName,child<childIndex+1>.
func (r *hostRunner) buildProcID(testIndex int) (string, error) {
	procID := r.procID
	if procID == "" {
		return fmt.Sprintf("test%d,child0", testIndex), nil
	}

	idParts := strings.Split(procID, ",")
	if len(idParts) != 2 {
		return "", fmt.Errorf("cannot parse process ID")
	}

	testName, procName := idParts[0], idParts[1]
	childIndex, err := strconv.Atoi(strings.TrimPrefix(procName, "child"))
	if err != nil {
		return "", fmt.Errorf("error parsing process name in process ID %q: %w", procName, err)
	}

	return fmt.Sprintf("%s,child%d", testName, childIndex+1), nil
}

// getCurrentExePath retrieves the current process executable path.
func getCurrentExePath() (string, error) {
	return os.Readlink(fmt.Sprintf("/proc/%d/exe", os.Getpid()))
}
