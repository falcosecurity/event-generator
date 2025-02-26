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

package container

import (
	"context"

	"github.com/go-logr/logr"
)

// Builder allows to build a new container.
type Builder interface {
	// SetLogger sets the container interface logger.
	SetLogger(logger logr.Logger)
	// SetImageName sets the name used to tag the base image. The new tagged image is the one used to spawn the
	// container in place of the base one.
	SetImageName(name string)
	// SetContainerName sets the container name.
	SetContainerName(name string)
	// SetEnv sets the list of environment variable that must be provided to the container, in addition to the default
	// ones.
	SetEnv(env []string)
	// SetEntrypoint sets the container entrypoint.
	SetEntrypoint(entrypoint []string)
	// Build builds the container.
	Build() Container
}

// Container represents a container.
type Container interface {
	// Start starts the container. It returns an error if the container was already started.
	Start(ctx context.Context) error
	// Wait waits for container termination. It returns an error if the container was not started or the container
	// process returned with an exit code different from zero.
	Wait(ctx context.Context) error
}
