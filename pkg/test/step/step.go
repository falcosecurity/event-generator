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

package step

import (
	"context"

	"github.com/falcosecurity/event-generator/pkg/test/field"
	"github.com/falcosecurity/event-generator/pkg/test/loader"
)

// A Step represent a single step in a test.
type Step interface {
	// Name returns the step name.
	Name() string
	// Run runs the step. If the step requires any binding to be performed, it must be done (by calling Bind), before
	// trying to run the step; otherwise, an error is returned.
	Run(ctx context.Context) error
	// Cleanup restores the environment to the state it was before running the step.
	Cleanup(ctx context.Context) error
	// Bind binds fields of the current step to values of other steps, as described by the provided bindings.
	Bind(bindings []*Binding) error
	// FieldBindings provides the list of field bindings.
	FieldBindings() []*FieldBinding
	field.Retriever
}

// A Binding is related to a specific step. It associates to a local field, the source field information needed in order
// to perform the binding.
type Binding struct {
	LocalField string
	SrcField   *field.Field
}

// A FieldBinding is related to a specific step. It associates to a local field, the source name and the source field
// name containing the value the local field should be bound to.
type FieldBinding struct {
	LocalField string
	SrcName    string
	SrcField   string
}

// Builder allows to build new test step.
type Builder interface {
	// Build builds a new test step.
	// TODO: replace loader.TestStep with a dedicated type.
	Build(testStep *loader.TestStep) (Step, error)
}
