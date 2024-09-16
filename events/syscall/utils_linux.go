//go:build linux
// +build linux

// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package syscall

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	sys "syscall"

	"github.com/falcosecurity/event-generator/events"
	"golang.org/x/sys/unix"
)

// becameUser calls looks up the username UID then calls "setuid" syscall.
//
// IMPORTANT NOTE: the behavior is unpredicatable when used with goroutes.
// On linux, setuid only affects the current thread, not the process.
// Thus, becameUser may or not affect other goroutines.
func becameUser(h events.Helper, username string) error {
	h.Log().WithField("user", username).
		Infof("became %q", username)

	u, err := user.Lookup(username)
	if err != nil {
		return err
	}

	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return err
	}

	h.Log().WithField("uid", sys.Getuid()).
		WithField("euid", sys.Geteuid()).Debug("pre setuid")

	uuid := uint(uid)
	_, _, errno := unix.RawSyscall(unix.SYS_SETUID, uintptr(uuid), 0, 0)

	h.Log().WithError(errno).
		WithField("uid", sys.Getuid()).
		WithField("euid", sys.Geteuid()).Debug("post setuid")

	if errno != 0 {
		return errno
	}
	return nil
}

func runAsUser(h events.Helper, username string, cmdName string, cmdArgs ...string) error {
	h.Log().WithField("user", username).
		WithField("cmdName", cmdName).
		WithField("cmdArgs", cmdArgs).
		Infof("run as %q", username)

	u, err := user.Lookup(username)
	if err != nil {
		return err
	}

	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return err
	}

	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return err
	}

	cmd := exec.Command(cmdName, cmdArgs...)
	cmd.SysProcAttr = &sys.SysProcAttr{}
	cmd.SysProcAttr.Credential = &sys.Credential{
		Uid: uint32(uid),
		Gid: uint32(gid),
	}

	// for easier debugging of errors, return the combined (stdout and stderr) output of the command execution
	if out, err := cmd.CombinedOutput(); err != nil {
		if o := strings.TrimSpace(string(out)); o != "" {
			// note: we might need to unwrap the error later on if we want to check the exit code
			// example: SystemUserInteractive event
			return fmt.Errorf("%w: %s", err, o)
		}
		return err
	}

	return nil
}

// createSshDirectoryUnderHome creates a temp directory under /home and .ssh directory inside it.
func createSshDirectoryUnderHome(h events.Helper) (string, func(), error) {
	// create a unique temp directory under /home
	tmpDir, err := os.MkdirTemp("/home", "falco-event-generator-syscall-SshDirectory-")
	if err != nil {
		return "", func() {}, err
	}

	// create .ssh subdirectory
	sshDir := filepath.Join(tmpDir, ".ssh")
	if err := os.Mkdir(sshDir, os.FileMode(0755)); err != nil {
		return "", func() {
			// any cleanup error should be logged but not returned
			if err := os.RemoveAll(tmpDir); err != nil {
				h.Log().WithError(err).Error("failed to remove temp directory")
			}
		}, err
	}

	return sshDir, func() {
		// any cleanup error should be logged but not returned
		if err := os.RemoveAll(tmpDir); err != nil {
			h.Log().WithError(err).Error("failed to remove temp directory")
		}
	}, nil
}
