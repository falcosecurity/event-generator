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

package base

import (
	"context"
	"fmt"
	"reflect"

	"github.com/falcosecurity/event-generator/pkg/test/field"
	"github.com/falcosecurity/event-generator/pkg/test/step"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall"
)

// baseSyscall represents a generic system call test step.
type baseSyscall struct {
	// stepName is the syscall step name.
	stepName string

	// argsContainer is a handle to the struct containing the syscall arguments that can be provided as value or by
	// binding. Fields values of the underlying struct can be set or retrieved.
	argsContainer reflect.Value
	// bindOnlyArgsContainer is a handle to the struct containing the syscall arguments that can only be provided by
	// binding. Fields values of the underlying struct can be set or retrieved.
	bindOnlyArgsContainer reflect.Value
	// retValueContainer is a handle to the struct containing the return value. The return value can only be retrieved,
	// but not set.
	retValueContainer reflect.Value

	// unboundArgs and unboundBindOnlyArgs accounts the remaining arguments that must be bound to something before being
	// able to Run the system call test step.
	unboundArgs         map[string]struct{}
	unboundBindOnlyArgs map[string]struct{}

	// fieldBindings is the list of field binding required to run the current system call step.
	fieldBindings []*step.FieldBinding

	// runFunc is the underlying implementation of the current step.
	runFunc func(ctx context.Context) error
	// cleanupFunc is the underlying implementation of the current step cleanup procedure.
	cleanupFunc func(ctx context.Context) error
}

// Verify that baseSyscall implements syscall.Syscall interface.
var _ syscall.Syscall = (*baseSyscall)(nil)

// New creates a new generic system call test step.
func New(stepName string, rawArgs map[string]string, fieldBindings []*step.FieldBinding, argsContainer,
	bindOnlyArgsContainer, retValueContainer reflect.Value, defaultedArgs []string,
	runFunc, cleanupFunc func(ctx context.Context) error) (syscall.Syscall, error) {
	if err := checkContainersInvariants(argsContainer, bindOnlyArgsContainer, retValueContainer); err != nil {
		return nil, err
	}

	if runFunc == nil {
		return nil, fmt.Errorf("run function must not be nil")
	}

	unboundArgs, err := setArgFieldValues(argsContainer, rawArgs)
	if err != nil {
		return nil, fmt.Errorf("error setting argument field values: %w", err)
	}

	unboundBindOnlyArgs := field.Paths(bindOnlyArgsContainer.Type())

	// Remove defaulted arguments from unbound arguments sets.
	for _, arg := range defaultedArgs {
		delete(unboundArgs, arg)
		delete(unboundBindOnlyArgs, arg)
	}

	s := &baseSyscall{
		stepName:              stepName,
		argsContainer:         argsContainer,
		bindOnlyArgsContainer: bindOnlyArgsContainer,
		retValueContainer:     retValueContainer,
		unboundArgs:           unboundArgs,
		unboundBindOnlyArgs:   unboundBindOnlyArgs,
		fieldBindings:         fieldBindings,
		runFunc:               runFunc,
		cleanupFunc:           cleanupFunc,
	}
	return s, nil
}

func checkContainersInvariants(argsContainer, bindOnlyArgsContainer, retValueContainer reflect.Value) error {
	if argsContainer.Kind() != reflect.Struct {
		return fmt.Errorf("args container must be a struct")
	}
	if bindOnlyArgsContainer.Kind() != reflect.Struct {
		return fmt.Errorf("bind-only args container must be a struct")
	}
	if retValueContainer.Kind() != reflect.Struct {
		return fmt.Errorf("ret value container must be a struct")
	}
	if !argsContainer.CanSet() {
		return fmt.Errorf("args container must be settable")
	}
	if !bindOnlyArgsContainer.CanSet() {
		return fmt.Errorf("bind-only args container must be settable")
	}
	return nil
}

// setArgFieldValues sets the argument fields in argFieldContainer to the corresponding values in rawArgs. It returns
// the set of arguments that remain to be set.
func setArgFieldValues(argFieldContainer reflect.Value, rawArgs map[string]string) (map[string]struct{}, error) {
	unboundArgs := field.Paths(argFieldContainer.Type())
	for rawArg, rawArgValue := range rawArgs {
		argField, err := field.ByName(rawArg, argFieldContainer)
		if err != nil {
			return nil, fmt.Errorf("error getting %q argument field info: %w", rawArg, err)
		}

		if err := setArgFieldValue(argField, rawArgValue); err != nil {
			return nil, fmt.Errorf("error setting %q argument field value to %q: %w", rawArg, rawArgValue, err)
		}

		delete(unboundArgs, field.Path(rawArg))
	}
	return unboundArgs, nil
}

// setArgFieldValue sets the value of the field identified by the provided field info to the provided value, parsing it
// differently depending on the field type.
func setArgFieldValue(argField *field.Field, value string) error {
	argFieldValue := argField.Value
	switch argFieldType := argField.Type; argFieldType {
	case field.TypeFD:
		fd, err := parseFD(value)
		if err != nil {
			return fmt.Errorf("cannot parse value as FD: %w", err)
		}
		argFieldValue.SetInt(int64(fd))
	case field.TypeUndefined:
		return fmt.Errorf("argument field type is undefined")
	default:
		return fmt.Errorf("unknown syscall argument field type %q", argFieldType)
	}

	return nil
}

func (s *baseSyscall) Name() string {
	return s.stepName
}

func (s *baseSyscall) Run(ctx context.Context) error {
	if s.unboundArgFieldsNum() > 0 {
		unboundArgFields := s.unboundArgFieldNames()
		return fmt.Errorf("the following argument fields are not bound yet: %v", unboundArgFields)
	}

	return s.runFunc(ctx)
}

// unboundArgFieldsNum returns the number of unbound argument fields.
func (s *baseSyscall) unboundArgFieldsNum() int {
	return len(s.unboundArgs) + len(s.unboundBindOnlyArgs)
}

// unboundArgFieldNames returns the names of the unbound argument fields.
func (s *baseSyscall) unboundArgFieldNames() []string {
	unboundArgFieldNames := make([]string, len(s.unboundArgs)+len(s.unboundBindOnlyArgs))
	i := 0
	for unboundArgFieldName := range s.unboundArgs {
		unboundArgFieldNames[i] = unboundArgFieldName
		i++
	}
	for unboundArgFieldName := range s.unboundBindOnlyArgs {
		unboundArgFieldNames[i] = unboundArgFieldName
		i++
	}
	return unboundArgFieldNames
}

func (s *baseSyscall) Cleanup(ctx context.Context) error {
	if s.cleanupFunc != nil {
		return s.cleanupFunc(ctx)
	}

	return nil
}

func (s *baseSyscall) Field(name string) (*field.Field, error) {
	argFieldContainers := []reflect.Value{s.retValueContainer, s.argsContainer, s.bindOnlyArgsContainer}
	return field.ByName(name, argFieldContainers...)
}

func (s *baseSyscall) Bind(bindings []*step.Binding) error {
	argFieldContainers := []reflect.Value{s.argsContainer, s.bindOnlyArgsContainer}
	return s.bindMultiple(bindings, argFieldContainers)
}

func (s *baseSyscall) FieldBindings() []*step.FieldBinding {
	return s.fieldBindings
}

func (s *baseSyscall) bindMultiple(bindings []*step.Binding, argFieldContainers []reflect.Value) error {
	for _, binding := range bindings {
		if err := bindSingle(binding, argFieldContainers); err != nil {
			return err
		}
		argFieldName := field.Path(binding.LocalField)
		// TODO: make deletion logic s.unboundArgs and s.unboundBindOnlyArgs more precise
		delete(s.unboundArgs, argFieldName)
		delete(s.unboundBindOnlyArgs, argFieldName)
	}
	return nil
}

func bindSingle(binding *step.Binding, argFieldContainers []reflect.Value) error {
	localArgField, err := field.ByName(binding.LocalField, argFieldContainers...)
	if err != nil {
		return err
	}

	srcArgField := binding.SrcField
	if err := localArgField.Set(srcArgField); err != nil {
		return fmt.Errorf("error setting field %q (%v) to %q (%v)", localArgField.Path,
			localArgField.Value.Interface(), srcArgField.Path, srcArgField.Value.Interface())
	}

	return nil
}
