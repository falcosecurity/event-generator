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

package test

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"

	"github.com/falcosecurity/event-generator/pkg/test/loader"
)

// Test represents a runnable test.
type Test interface {
	// Run runs the test.
	Run(ctx context.Context) error
}

// ResourceCreationError is an error produced while creating a test resource.
type ResourceCreationError struct {
	ResourceName  string
	ResourceIndex int
	Err           error
}

func (e *ResourceCreationError) Error() string {
	return fmt.Sprintf("error creating resource %q, index %d: %v", e.ResourceName, e.ResourceIndex, e.Err)
}

// StepRunError is an error produced while running a test step.
type StepRunError struct {
	StepName  string
	StepIndex int
	Err       error
}

func (e *StepRunError) Error() string {
	return fmt.Sprintf("error running step %q, index %d: %v", e.StepName, e.StepIndex, e.Err)
}

// Builder allows to build new test.
type Builder interface {
	// Build builds a new test.
	Build(logger logr.Logger, testDesc *loader.Test) (Test, error)
}

// ResourceBuildError is an error produced while building a test resource.
type ResourceBuildError struct {
	ResourceName  string
	ResourceIndex int
	Err           error
}

func (e *ResourceBuildError) Error() string {
	return fmt.Sprintf("error building resource %q, index %d: %v", e.ResourceName, e.ResourceIndex, e.Err)
}

// StepBuildError is an error produced while building a test step.
type StepBuildError struct {
	StepName  string
	StepIndex int
	Err       error
}

func (e *StepBuildError) Error() string {
	return fmt.Sprintf("error building step %q, index %d: %v", e.StepName, e.StepIndex, e.Err)
}
