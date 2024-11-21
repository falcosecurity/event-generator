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
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/go-logr/logr"
	"golang.org/x/sys/unix"

	"github.com/falcosecurity/event-generator/pkg/capability"
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
	// username is the name of the user that must run the process. If empty, the current process user is used. If the
	// specified user does not exist, it is created before running the test and deleted after test execution.
	username string
	// capabilities are the capabilities that must be set on the process executable file. The syntax follows the
	// conventions specified by cap_from_text(3). Notice: an empty string defaults to 'all=iep'.
	capabilities string
	// cmd is the underlying command object.
	cmd *exec.Cmd
	// started is true if the process has been started; false otherwise.
	started bool
	// userCreated is true if the user has been created; false otherwise.
	userCreated bool
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
	// Username is the name of the user that must run the process. If empty, the current process user is used. If the
	// specified user does not exist, it is created before running the test and deleted after test execution.
	Username string
	// Capabilities are the capabilities that must be set on the process executable file. The syntax follows the
	// conventions specified by cap_from_text(3). Notice: an empty string defaults to 'all=iep'.
	Capabilities string
}

var (
	// defaultSimExePathPrefix defines the prefix used to generate a random simulated executable path.
	defaultSimExePathPrefix = filepath.Join(os.TempDir(), "event-generator")
)

var allCaps = "all=iep"

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

	// If the user doesn't provide capabilities, we default them.
	var capabilities string
	if procDesc.Capabilities != "" {
		capabilities = procDesc.Capabilities
	} else {
		capabilities = allCaps
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
		logger:       procDesc.Logger,
		command:      procDesc.Command,
		simExePath:   simExePath,
		username:     procDesc.Username,
		capabilities: capabilities,
		cmd:          cmd,
		started:      false,
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

	// Determine if the process must be run by the current user/group or not. If a user different from the current one
	// is requested to run it, the user is created at this stage, and deleted after the new process resources are
	// released.
	changeOwnership := false
	userCreated := false
	var procUID, procGID int
	if username := p.username; username != "" {
		userCreated, procUID, procGID, err = p.findOrCreateUser(username)
		if err != nil {
			return fmt.Errorf("error finding or creating user %q: %w", username, err)
		}

		logger := p.logger.WithValues("user", username, "uid", procUID, "gid", procGID)
		if userCreated {
			defer p.deleteUserIfErr(username, &err)
			logger.V(1).Info("Created user")
		} else {
			logger.V(1).Info("Found user")
		}

		// The current executable must be run with real IDs set to 0, so compare the obtained IDs with the effective
		// ones instead of the real ones.
		changeOwnership = procUID != os.Geteuid() || procGID != os.Getegid()
	}

	capabilities := p.capabilities
	changeCapabilities := capabilities != allCaps

	// Create the simulated executable file. It is either a hard link or a copy of the original command path, depending
	// on the fact that it is required to change the file ownership/capabilities or not.
	simExePath := p.simExePath
	if changeOwnership || changeCapabilities {
		// We are going to manipulate the file ownership and capabilities, so create a copy of the original instead of
		// modifying the original one.
		if err := copyFile(commandPath, simExePath); err != nil {
			return fmt.Errorf("error copying process executable: %w", err)
		}
		defer p.removeFileIfErr(simExePath, &err)
		p.logger.V(1).Info("Created process executable", "path", simExePath)

		if changeOwnership {
			if err := os.Chown(simExePath, procUID, procGID); err != nil {
				return fmt.Errorf("error changing process executable ownership to %d:%d: %w", procUID, procGID, err)
			}
		}

		if err := p.setFileCapabilities(simExePath, capabilities); err != nil {
			return fmt.Errorf("error setting process executable file capabilities to %q: %w", capabilities, err)
		}

		if changeOwnership {
			if err := os.Chmod(simExePath, 0o555|os.ModeSetuid|os.ModeSetgid); err != nil {
				return fmt.Errorf("error changing process executable file mode: %w", err)
			}
		}
	} else {
		if err := os.Link(commandPath, simExePath); err != nil {
			return fmt.Errorf("error creating process executable: %w", err)
		}
		defer p.removeFileIfErr(simExePath, &err)
		p.logger.V(1).Info("Created process executable", "path", simExePath)

		if err := p.setFileCapabilities(simExePath, capabilities); err != nil {
			return fmt.Errorf("error setting process executable file capabilities to %q: %w", capabilities, err)
		}
	}

	// If the user specified a custom process name, we will run the executable through a symbolic link, so create it.
	exePath := p.cmd.Path
	if simExePath != exePath {
		if err := os.Symlink(simExePath, exePath); err != nil {
			return fmt.Errorf("error creating symlink %q to process executable %q: %w", exePath, simExePath,
				err)
		}
		defer p.removeFileIfErr(exePath, &err)
		p.logger.V(1).Info("Created symlink to process executable", "path", simExePath, "symlink", exePath)
	}

	// Run the executable but prevent the kernel from ignoring file capabilities when real/effective user ID is 0 (see
	// 'Capabilities and execution of programs by root' in capabilities(7)).
	// Notice: secure bits are inherited by child process, so whatever process is going to be spawned by our child will
	// not inherit root privileges if our child doesn't clear the SECBIT_NOROOT first.
	if err := capability.RunWithSecBitNoRootEnabled(p.cmd.Start); err != nil {
		return err
	}

	p.started = true
	p.userCreated = userCreated
	return nil
}

// findOrCreateUser finds or creates the user with the provided username. It returns information about the user.
func (p *Process) findOrCreateUser(username string) (created bool, uid, gid int, err error) {
	if uid, gid, err = getUserIDs(username); err == nil {
		return false, uid, gid, nil
	}

	var unknownUserErr user.UnknownUserError
	if !errors.As(err, &unknownUserErr) {
		return false, 0, 0, fmt.Errorf("error retrieving user id: %w", err)
	}

	// User does not exist, create it.
	if err := addUser(username); err != nil {
		_ = delUser(username) // addUser can leave an inconsistent state.
		return false, 0, 0, fmt.Errorf("error creating user: %w", err)
	}
	defer p.deleteUserIfErr(username, &err)

	// Retrieve the user ID of the created user.
	if uid, gid, err = getUserIDs(username); err != nil {
		return false, 0, 0, fmt.Errorf("error looking up for user after creation: %w", err)
	}

	return true, uid, gid, nil
}

// getUserIDs returns the user and group IDs of the user associated to the provided username.
func getUserIDs(username string) (uid, gid int, err error) {
	usr, err := user.Lookup(username)
	if err != nil {
		return 0, 0, fmt.Errorf("error looking up user %q: %w", username, err)
	}

	if uid, err = strconv.Atoi(usr.Uid); err != nil {
		return 0, 0, fmt.Errorf("error parsing user uid %q: %w", usr.Uid, err)
	}

	if gid, err = strconv.Atoi(usr.Gid); err != nil {
		return 0, 0, fmt.Errorf("error parsing user gid %q: %w", usr.Gid, err)
	}

	return uid, gid, nil
}

// addUser creates a user with the given username.
func addUser(username string) error {
	return capability.RunWithSecBitNoRootDisabled(func() error {
		return exec.Command("sh", "-c", fmt.Sprintf("useradd %q", username)).Run() //nolint:gosec // Disable G204
	})
}

// delUser deletes the user with the given username.
func delUser(username string) error {
	return capability.RunWithSecBitNoRootDisabled(func() error {
		return exec.Command("sh", "-c", fmt.Sprintf("userdel %q", username)).Run() //nolint:gosec // Disable G204
	})
}

// deleteUserIfErr deletes the user associated to the provided username if the provided error pointer points to an
// error.
func (p *Process) deleteUserIfErr(username string, err *error) { //nolint:gocritic // Disable ptrToRefParam
	if *err != nil {
		if err := delUser(username); err != nil {
			p.logger.Error(err, "Error deleting user", "user", username)
		}
	}
}

// copyFile copies the file at src to dst.
func copyFile(src, dst string) (err error) {
	srcFile, err := os.Open(src) //nolint:gosec // Disable G304
	if err != nil {
		return fmt.Errorf("error opening source file: %w", err)
	}
	defer func() {
		if e := srcFile.Close(); e != nil {
			e := fmt.Errorf("error closing source file: %w", e)
			if err != nil {
				err = fmt.Errorf("%w; %w", err, e)
			} else {
				err = e
			}
		}
	}()

	dstFile, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE, 0o755) //nolint:gosec // Disable G304
	if err != nil {
		return fmt.Errorf("error creating destination file: %w", err)
	}
	defer func() {
		if e := dstFile.Close(); e != nil {
			e := fmt.Errorf("error closing destination file: %w", e)
			if err != nil {
				err = fmt.Errorf("%w; %w", err, e)
			} else {
				err = e
			}
		}
	}()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return fmt.Errorf("error copying data: %w", err)
	}

	return nil
}

// removeFileIfErr removes the file at the provided file path if the provided error pointer points to an error.
func (p *Process) removeFileIfErr(filePath string, err *error) { //nolint:gocritic // Disable ptrToRefParam
	if *err != nil {
		if err := os.Remove(filePath); err != nil {
			p.logger.Error(err, "Error deleting file", "path", filePath)
		}
	}
}

// setFileCapabilities sets the capability state of the file at the provided file path to the value obtained parsing
// the provided capability string.
func (p *Process) setFileCapabilities(filePath, capabilities string) error {
	caps, err := capability.Parse(capabilities)
	if err != nil {
		return fmt.Errorf("error parsing capabilities: %w", err)
	}

	file, err := os.Open(filePath) //nolint:gosec // Disable G304
	if err != nil {
		return fmt.Errorf("error opening file: %w", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			p.logger.Error(err, "Error closing executable after setting capabilities")
		}
	}()

	return caps.SetFd(file)
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
	defer func() {
		p.started = false
		p.userCreated = false
	}()

	username := p.username
	if p.userCreated {
		if err := delUser(username); err != nil {
			p.logger.Error(err, "Error deleting user", "user", username)
		} else {
			p.logger.V(1).Info("Deleted user", "user", username)
		}
	}

	simExePath := p.simExePath
	exePath := p.cmd.Path
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
