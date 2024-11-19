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

package process

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"

	"github.com/go-logr/logr"
	"golang.org/x/sys/unix"

	"github.com/falcosecurity/event-generator/pkg/random"
)

// Process represent an OS process.
type Process struct {
	logger logr.Logger
	// command is the command the process is associated with.
	command string
	// simExePath is the "simulated" executable path. This sets the executable path accessible through
	// `readlink -f /proc/<pid/exepath` for the started process. If empty, it is randomly generated.
	simExePath string
	// cmd is the underlying command object.
	cmd *exec.Cmd
	// started is true if the process has been started; false otherwise.
	started bool
}

// Description describes a process.
type Description struct {
	Logger logr.Logger
	// The command to be run.
	Command string
	// SimExePath is the "simulated" executable path. This sets the executable path accessible through
	// `readlink -f /proc/<pid/exepath` for the started process. If empty, it is randomly generated.
	SimExePath string
	// Name is the process name. If omitted, it defaults to filepath.Base(SimExePath).
	Name string
	// Arg0 is the argument in position 0 (a.k.a. argv[0]) of the process. If empty, it defaults to Name if this is
	// not empty; otherwise, it defaults to filepath.Base(SimExePath).
	Arg0 string
	// Args is a string containing the space-separated list of command line arguments. If a single argument contains
	// spaces, the entire argument must be quoted in order to not be considered as multiple arguments.
	Args string
	// Env is the list of environment variables that must be provided to the process.
	Env []string
}

var (
	// defaultSimExePathPrefix defines the prefix used to generate a random simulated executable path.
	defaultSimExePathPrefix = filepath.Join(os.TempDir(), "event-generator")
)

// New creates a new process.
func New(ctx context.Context, procDesc *Description) *Process {
	// If the user doesn't provide an executable path, we must generate a random path.
	var simExePath string
	if exePath := procDesc.SimExePath; exePath != "" {
		simExePath = exePath
	} else {
		simExePath = defaultSimExePathPrefix + random.Seq(10)
	}

	// If the user provides a process name, we must run the executable through a symbolic link having the provided name
	// and pointing to the simulated executable path. Create the symbolic link under the directory of the simulated
	// executable.
	var exePath string
	if name := procDesc.Name; name != "" {
		exePath = filepath.Join(filepath.Dir(simExePath), name)
	} else {
		exePath = simExePath
	}

	// If the user provides the argument zero, set the argument zero of the new process to its value; otherwise defaults
	// it to the last segment of the executable path.
	var procArg0 string
	if arg0 := procDesc.Arg0; arg0 != "" {
		procArg0 = arg0
	} else {
		procArg0 = filepath.Base(exePath)
	}

	// Evaluate process arguments.
	procArgs := splitArgs(procDesc.Args)

	// Setup process command.
	cmd := exec.CommandContext(ctx, exePath, procArgs...) //nolint:gosec // Disable G204
	cmd.Args[0] = procArg0
	cmd.Env = procDesc.Env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	proc := &Process{
		logger:     procDesc.Logger,
		command:    procDesc.Command,
		simExePath: simExePath,
		cmd:        cmd,
		started:    false,
	}
	return proc
}

// splittingArgsRegex allows to split space-separated arguments, keeping together space-separated words under the same
// single- or double-quoted group.
var splittingArgsRegex = regexp.MustCompile(`"([^"]+)"|'([^']+)'|(\S+)`)

// splitArgs splits the provided space-separated arguments. If a group composed of space-separated words must be
// considered as a single argument, it must be single- or double-quoted.
func splitArgs(args string) []string {
	if args == "" {
		return nil
	}

	matches := splittingArgsRegex.FindAllStringSubmatch(args, -1)
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

// Start the process.
func (p *Process) Start() (err error) {
	// Retrieve the specified command path.
	commandPath, err := exec.LookPath(p.command)
	if err != nil && !errors.Is(err, exec.ErrDot) {
		return fmt.Errorf("error retrieving command path: %w", err)
	}

	// Create a hard link to the provided command path, named as specified by the user.
	simExePath := p.simExePath
	if err := os.Link(commandPath, simExePath); err != nil {
		return fmt.Errorf("error creating process executable: %w", err)
	}
	defer func() {
		if err != nil {
			if err := os.Remove(simExePath); err != nil {
				p.logger.Error(err, "Error deleting process executable", "path", simExePath)
			}
		}
	}()
	p.logger.V(1).Info("Created process executable", "path", simExePath)

	// If the user specified a custom process name, we will run the executable through a symbolic link, so create it.
	exePath := p.cmd.Path
	if simExePath != exePath {
		if err := os.Symlink(simExePath, exePath); err != nil {
			return fmt.Errorf("error creating symlink %q to process executable %q: %w", exePath, simExePath,
				err)
		}
		defer func() {
			if err != nil {
				if err := os.Remove(exePath); err != nil {
					p.logger.Error(err, "Error deleting symlink to process executable", "symlink", exePath)
				}
			}
		}()
	}
	p.logger.V(1).Info("Created symlink to process executable", "path", simExePath, "symlink", exePath)

	// Run the process.
	if err := p.cmd.Start(); err != nil {
		return err
	}

	p.started = true
	return nil
}

var errProcessNotStarted = fmt.Errorf("process not started")

// Wait waits for process to exit and releases the related resources.
func (p *Process) Wait() error {
	if !p.started {
		return errProcessNotStarted
	}

	defer p.releaseResources()

	if err := p.cmd.Wait(); err != nil {
		return err
	}

	return nil
}

// Kill kills the process and releases the related resources.
func (p *Process) Kill() error {
	if !p.started {
		return errProcessNotStarted
	}

	defer p.releaseResources()

	if err := p.cmd.Process.Signal(unix.SIGKILL); err != nil {
		return fmt.Errorf("error sending sigkill to process: %w", err)
	}

	if err := p.cmd.Wait(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			if terminatedBySignal := !exitErr.ProcessState.Exited(); terminatedBySignal {
				return nil
			}
		}
		return fmt.Errorf("error waiting for process: %w", err)
	}

	return nil
}

// releaseResources releases the resources associated to the process, such as created executables.
func (p *Process) releaseResources() {
	simExePath := p.simExePath
	exePath := p.cmd.Path
	defer func() {
		p.started = false
	}()

	if simExePath != exePath {
		if err := os.Remove(exePath); err != nil {
			p.logger.Error(err, "Error deleting symlink to process executable", "symlink", exePath)
		} else {
			p.logger.V(1).Info("Deleted symlink to process executable", "symlink", exePath)
		}
	}

	if err := os.Remove(simExePath); err != nil {
		p.logger.Error(err, "Error deleting process executable", "path", simExePath)
	}
	p.logger.V(1).Info("Deleted process executable", "path", simExePath)
}

// PID returns the process identifier.
func (p *Process) PID() int {
	return p.cmd.Process.Pid
}
