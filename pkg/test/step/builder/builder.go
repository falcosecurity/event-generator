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
	"fmt"

	"github.com/falcosecurity/event-generator/pkg/test/loader"
	"github.com/falcosecurity/event-generator/pkg/test/step"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall"
)

// builder is an implementation of step.Builder.
type builder struct {
	syscallBuilder syscall.Builder
}

// Verify that builder implements step.Builder interface.
var _ step.Builder = (*builder)(nil)

// New creates a new builder.
func New(syscallBuilder syscall.Builder) (step.Builder, error) {
	if syscallBuilder == nil {
		return nil, fmt.Errorf("system call test step builder must not be nil")
	}

	return &builder{syscallBuilder: syscallBuilder}, nil
}

func (b *builder) Build(testStep *loader.TestStep) (step.Step, error) {
	switch testStep.Type {
	case loader.TestStepTypeSyscall:
		syscallSpec, ok := testStep.Spec.(*loader.TestStepSyscallSpec)
		if !ok {
			return nil, fmt.Errorf("cannot parse system call spec")
		}

		fieldBindings := convertFieldBindings(testStep.FieldBindings)
		return b.syscallBuilder.Build(
			syscall.Name(syscallSpec.Syscall),
			testStep.Name,
			&syscall.Description{RawArgs: syscallSpec.Args, FieldBindings: fieldBindings},
		)
	default:
		return nil, fmt.Errorf("unknown test step type %q", testStep.Type)
	}
}

// TODO: remove this function when Build will accept a dedicated type.
func convertFieldBindings(fieldBindings []*loader.TestStepFieldBinding) []*step.FieldBinding {
	bindings := make([]*step.FieldBinding, len(fieldBindings))
	for i, fieldBinding := range fieldBindings {
		bindings[i] = &step.FieldBinding{
			LocalField: fieldBinding.LocalField,
			SrcName:    fieldBinding.SrcStep,
			SrcField:   fieldBinding.SrcField,
		}
	}
	return bindings
}
