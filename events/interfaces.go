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

package events

import (
	"fmt"
	"time"

	logger "github.com/sirupsen/logrus"
	"k8s.io/cli-runtime/pkg/resource"
)

// ErrSkipped must be returned by an action when skipped for any reason.
type ErrSkipped struct {
	Reason string
}

func (e *ErrSkipped) Error() string {
	return fmt.Sprintf("action skipped: %s", e.Reason)
}

// A Helper is passed to an Action as argument.
type Helper interface {

	// Log returns an intermediate logger.Entry
	// that already contains default fields for the current action.
	Log() *logger.Entry

	// Sleep pauses the current goroutine for at least the given duration and logs that.
	Sleep(time.Duration)

	// Cleanup registers a function to be called when the action complete or later.
	// Cleanup functions registered from within the same action will be called in last added,
	// first called order.
	Cleanup(f func(), args ...interface{})

	// SpawnAs starts a child process and waits for it to complete.
	// The child runs the given action as a different program name.
	SpawnAs(name string, action string, args ...string) error

	// Spawned returns true if the action is running in a child process.
	Spawned() bool

	// ResourceBuilder returns a k8s' resource.Builder.
	ResourceBuilder() *resource.Builder

	// InContainer returns true if the application is running in a container.
	// Useful to skip actions which won't work within a container.
	InContainer() bool
}

// An Action triggers an event.
type Action func(Helper) error
