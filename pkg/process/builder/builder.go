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

package builder

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
	"github.com/falcosecurity/event-generator/pkg/osutil"
	"github.com/falcosecurity/event-generator/pkg/process"
	"github.com/falcosecurity/event-generator/pkg/random"
)

// builder is an implementation of process.Builder.
type builder struct {
	simExePath   string
	name         string
	arg0         string
	args         string
	env          []string
	username     string
	capabilities string
}

// Verify that builder implements process.Builder interface.
var _ process.Builder = (*builder)(nil)

// New creates a new process builder.
func New() process.Builder {
	b := &builder{}
	return b
}

func (b *builder) SetSimExePath(simExePath string) {
	b.simExePath = simExePath
}

func (b *builder) SetName(name string) {
	b.name = name
}

func (b *builder) SetArg0(arg0 string) {
	b.arg0 = arg0
}

func (b *builder) SetArgs(args string) {
	b.args = args
}

func (b *builder) SetEnv(env []string) {
	b.env = env
}

func (b *builder) SetUsername(username string) {
	b.username = username
}

func (b *builder) SetCapabilities(capabilities string) {
	b.capabilities = capabilities
}

var (
	// defaultSimExePathPrefix defines the prefix used to generate a random simulated executable path.
	defaultSimExePathPrefix = filepath.Join(os.TempDir(), "event-generator")
	// defaultCapabilities defines the default capability string used if it is not specified or unset.
	defaultCapabilities = "all=iep"
)

func (b *builder) Build(ctx context.Context, logger logr.Logger, command string) process.Process {
	defer b.reset()

	// If the user doesn't provide an executable path, we must generate a random path.
	var simExePath string
	if exePath := b.simExePath; exePath != "" {
		simExePath = exePath
	} else {
		simExePath = defaultSimExePathPrefix + random.Seq(10)
	}

	// If the user provides a process name, we must run the executable through a symbolic link having the provided name
	// and pointing to the simulated executable path. Create the symbolic link under the directory of the simulated
	// executable.
	var exePath string
	if name := b.name; name != "" {
		exePath = filepath.Join(filepath.Dir(simExePath), name)
	} else {
		exePath = simExePath
	}

	// If the user provides the argument zero, set the argument zero of the new process to its value; otherwise defaults
	// it to the last segment of the executable path.
	var procArg0 string
	if arg0 := b.arg0; arg0 != "" {
		procArg0 = arg0
	} else {
		procArg0 = filepath.Base(exePath)
	}

	// If the user doesn't provide capabilities, we default them.
	var capabilities string
	if b.capabilities != "" {
		capabilities = b.capabilities
	} else {
		capabilities = defaultCapabilities
	}

	// Evaluate process arguments.
	procArgs := splitArgs(b.args)

	// Setup process command.
	cmd := exec.CommandContext(ctx, exePath, procArgs...) //nolint:gosec // Disable G204
	cmd.Args[0] = procArg0
	cmd.Env = b.env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	proc := &osProcess{
		logger:       logger,
		command:      command,
		simExePath:   simExePath,
		username:     b.username,
		capabilities: capabilities,
		cmd:          cmd,
		started:      false,
	}

	return proc
}

// reset resets the underlying builder configuration to a default state.
func (b *builder) reset() {
	b.simExePath = ""
	b.name = ""
	b.arg0 = ""
	b.args = ""
	b.env = nil
	b.username = ""
	b.capabilities = ""
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

// osProcess represent an OS process.
type osProcess struct {
	logger       logr.Logger
	command      string
	simExePath   string
	username     string
	capabilities string

	// cmd is the underlying command object.
	cmd *exec.Cmd
	// started is true if the process has been started; false otherwise.
	started bool
	// userCreated is true if the user has been created; false otherwise.
	userCreated bool
	// firstCreatedSimExePathDir stores the path of the first directory, in the directory path leading to the
	// simulated executable path, that has been created. If no directories have been created, it is empty. If non-empty,
	// this is the directory that must be deleted upon process resources release.
	firstCreatedSimExePathDir string
}

// Verify that osProcess implements process.Process interface.
var _ process.Process = (*osProcess)(nil)

var (
	errProcessAlreadyStarted = fmt.Errorf("process already started")
	errProcessNotStarted     = fmt.Errorf("process not started")
)

func (p *osProcess) Start() (err error) {
	if p.started {
		return errProcessAlreadyStarted
	}

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

	simExePath := p.simExePath

	// Ensure the directory hierarchy containing the simulated executable file exists.
	simExePathDir := filepath.Dir(simExePath)
	firstCreatedSimExePathDir, err := osutil.MkdirAll(simExePathDir)
	if err != nil {
		return fmt.Errorf("error creating non-existing directories on process executable directory path %q: %w",
			simExePathDir, err)
	}
	if firstCreatedSimExePathDir != "" {
		p.logger.V(1).Info("Created directory hierarchy leading to process executable", "dirHierarchyRootPath",
			firstCreatedSimExePathDir)
	}
	defer p.removeDirHierarchyIfErr(firstCreatedSimExePathDir, &err)

	capabilities := p.capabilities
	changeCapabilities := capabilities != defaultCapabilities
	// Create the simulated executable file. It is either a hard link or a copy of the original command path, depending
	// on the fact that it is required to change the file ownership/capabilities or not.
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

		if err := capability.SetFile(simExePath, capabilities); err != nil {
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

		if err := capability.SetFile(simExePath, capabilities); err != nil {
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
	p.firstCreatedSimExePathDir = firstCreatedSimExePathDir
	return nil
}

// findOrCreateUser finds or creates the user with the provided username. It returns information about the user.
func (p *osProcess) findOrCreateUser(username string) (created bool, uid, gid int, err error) {
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
func (p *osProcess) deleteUserIfErr(username string, err *error) { //nolint:gocritic // Disable ptrToRefParam
	if *err != nil {
		if err := delUser(username); err != nil {
			p.logger.Error(err, "Error deleting user", "user", username)
		}
	}
}

// removeDirHierarchyIfErr removes the directory hierarchy starting at the provided directory path if the provided error
// pointer points to an error.
func (p *osProcess) removeDirHierarchyIfErr(dirPath string, err *error) { //nolint:gocritic // Disable ptrToRefParam
	if *err != nil {
		if err := os.RemoveAll(dirPath); err != nil {
			p.logger.Error(err, "Error deleting directory", "dirHierarchyRootPath", dirPath)
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
func (p *osProcess) removeFileIfErr(filePath string, err *error) { //nolint:gocritic // Disable ptrToRefParam
	if *err != nil {
		if err := os.Remove(filePath); err != nil {
			p.logger.Error(err, "Error deleting file", "path", filePath)
		}
	}
}

func (p *osProcess) Wait() error {
	if !p.started {
		return errProcessNotStarted
	}

	defer p.releaseResources()

	if err := p.cmd.Wait(); err != nil {
		return err
	}

	return nil
}

func (p *osProcess) Kill() error {
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
func (p *osProcess) releaseResources() {
	defer func() {
		p.started = false
		p.userCreated = false
	}()

	username := p.username
	if p.userCreated {
		logger := p.logger.WithValues("user", username)
		if err := delUser(username); err != nil {
			logger.Error(err, "Error deleting user")
		} else {
			logger.V(1).Info("Deleted user")
		}
	}

	simExePath := p.simExePath
	exePath := p.cmd.Path
	if simExePath != exePath {
		logger := p.logger.WithValues("symlink", exePath)
		if err := os.Remove(exePath); err != nil {
			logger.Error(err, "Error deleting symlink to process executable")
		} else {
			logger.V(1).Info("Deleted symlink to process executable")
		}
	}

	{ // Create a new scope just to define a new logger.
		logger := p.logger.WithValues("path", simExePath)
		if err := os.Remove(simExePath); err != nil {
			logger.Error(err, "Error deleting process executable")
		} else {
			logger.V(1).Info("Deleted process executable")
		}
	}

	if dirPath := p.firstCreatedSimExePathDir; dirPath != "" {
		logger := p.logger.WithValues("dirHierarchyRootPath", dirPath)
		if err := os.RemoveAll(dirPath); err != nil {
			logger.Error(err, "Error deleting directory hierarchy containing process executable")
		} else {
			logger.V(1).Info("Deleted directory hierarchy containing process executable")
		}
	}
}

func (p *osProcess) PID() int {
	return p.cmd.Process.Pid
}
