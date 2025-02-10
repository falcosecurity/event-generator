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

package process

import (
	"context"

	"github.com/go-logr/logr"
)

// Builder allows to build a new process.
type Builder interface {
	// SetSimExePath sets the "simulated" executable path. This sets the executable path accessible through
	// `readlink -f /proc/<pid/exepath` for the started process. If unset or empty, it is randomly generated.
	SetSimExePath(simExePath string)
	// SetName is the process name. If unset or empty, it defaults to filepath.Base(SimExePath).
	SetName(name string)
	// SetArg0 sets the argument in position 0 (a.k.a. argv[0]) of the process. If unset or empty, it defaults to the
	// process name if this is not empty; otherwise, it defaults to filepath.Base(SimExePath).
	SetArg0(arg0 string)
	// SetArgs sets the process arguments. It accepts a string containing the space-separated list of command line
	// arguments. If a single argument contains spaces, the entire argument must be quoted in order to not be considered
	// as multiple arguments.
	SetArgs(args string)
	// SetEnv sets the list of environment variables that must be provided to the process.
	SetEnv(env []string)
	// SetUsername sets the name of the user that must run the process. If unset or empty, the current process user is
	// used. If the specified user does not exist, it is created before running the test and deleted after test
	// execution.
	SetUsername(username string)
	// SetCapabilities sets the capabilities that must be set on the process executable file. The syntax follows the
	// conventions specified by cap_from_text(3). If unset or empty, it defaults to 'all=iep'.
	SetCapabilities(capabilities string)
	// Build builds the process. After calling Build, the Builder process-related configuration is cleared and the
	// Builder can be reused to build another process.
	Build(ctx context.Context, logger logr.Logger, command string) Process
}

// Process represents a runnable process.
type Process interface {
	// Start starts the process.
	Start() error
	// Wait waits for process to exit and releases the related resources.
	Wait() error
	// Kill kills the process and releases the related resources.
	Kill() error
	// PID returns the process identifier.
	PID() int
}
