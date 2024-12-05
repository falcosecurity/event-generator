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

var errOpenModeMustBePositive = fmt.Errorf("open mode must be a positive integer")

// New creates a new generic system call test step.
func New(stepName string, rawArgs map[string]any, fieldBindings []*step.FieldBinding, argsContainer,
	bindOnlyArgsContainer, retValueContainer reflect.Value, defaultedArgs []string,
	runFunc, cleanupFunc func(ctx context.Context) error) (syscall.Syscall, error) {
	if err := checkContainersInvariants(argsContainer, bindOnlyArgsContainer, retValueContainer); err != nil {
		return nil, err
	}

	if runFunc == nil {
		return nil, fmt.Errorf("run function must not be nil")
	}

	unboundArgs := field.Paths(argsContainer.Type())
	boundArgs, err := setArgFieldValues(argsContainer, rawArgs)
	if err != nil {
		return nil, fmt.Errorf("error setting argument field values: %w", err)
	}
	for _, boundArg := range boundArgs {
		delete(unboundArgs, boundArg)
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
// the list of set arguments field paths.
func setArgFieldValues(argFieldContainer reflect.Value, rawArgs map[string]any) ([]string, error) {
	var boundArgs []string
	for rawArg, rawArgValue := range rawArgs {
		argField, err := field.ByName(rawArg, argFieldContainer)
		if err != nil {
			return nil, fmt.Errorf("error getting %q argument field: %w", rawArg, err)
		}

		argFieldBoundArgs, err := setArgFieldValue(argField, rawArgValue)
		if err != nil {
			return nil, fmt.Errorf("error setting %q argument field value to %v: %w", rawArg, rawArgValue, err)
		}

		boundArgs = append(boundArgs, argFieldBoundArgs...)
	}
	return boundArgs, nil
}

// setArgFieldValue sets the value of the provided field and/or sub-fields to the provided value, parsing it differently
// depending on the field type.
//
//nolint:gocyclo // Disable cyclomatic complexity check.
func setArgFieldValue(argField *field.Field, value any) ([]string, error) {
	boundArgs := []string{argField.Path}
	argFieldValue := argField.Value
	switch argFieldType := argField.Type; argFieldType {
	case field.TypeFD:
		fd, err := parseInt64(value)
		if err != nil {
			return nil, fmt.Errorf("cannot parse value as fd: %w", err)
		}
		argFieldValue.SetInt(fd)
	case field.TypeBuffer:
		buffer, err := parseString(value)
		if err != nil {
			return nil, fmt.Errorf("cannot parse value as buffer: %w", err)
		}
		argFieldValue.Set(reflect.ValueOf([]byte(buffer)))
	case field.TypeBufferLen:
		bufferLen, err := parseBufferLen(value)
		if err != nil {
			return nil, fmt.Errorf("cannot parse value as buffer length: %w", err)
		}
		argFieldValue.SetInt(bufferLen)
	case field.TypeFilePath:
		filePath, err := parseFilePath(value)
		if err != nil {
			return nil, fmt.Errorf("cannot parse value as file path: %w", err)
		}
		argFieldValue.Set(reflect.ValueOf(filePath))
	case field.TypeOpenFlags, field.TypeOpenHowFlags:
		openFlags, err := parseFlags(value, openFlags)
		if err != nil {
			return nil, fmt.Errorf("cannot parse value as open flags: %w", err)
		}
		if argFieldValue.CanInt() {
			argFieldValue.SetInt(int64(openFlags))
		} else {
			argFieldValue.SetUint(uint64(openFlags)) //nolint:gosec // Disable G115
		}
	case field.TypeOpenMode, field.TypeOpenHowMode:
		openMode, err := parseFlags(value, openModes)
		if err != nil {
			return nil, fmt.Errorf("cannot parse value as open mode: %w", err)
		}
		if openMode < 0 {
			return nil, errOpenModeMustBePositive
		}
		argFieldValue.SetUint(uint64(openMode))
	case field.TypeOpenHow:
		fieldBoundArgs, err := setSubArgFieldValues(argField, value)
		if err != nil {
			return nil, fmt.Errorf("cannot parse value as open_how struct: %w", err)
		}
		boundArgs = append(boundArgs, fieldBoundArgs...)
	case field.TypeOpenHowResolve:
		resolveFlags, err := parseFlags(value, openHowResolveFlags)
		if err != nil {
			return nil, fmt.Errorf("cannot parse value as open resolve value: %w", err)
		}
		argFieldValue.SetUint(uint64(resolveFlags)) //nolint:gosec // Disable G115
	case field.TypeLinkAtFlags:
		linkAtFlags, err := parseFlags(value, linkAtFlags)
		if err != nil {
			return nil, fmt.Errorf("cannot parse value as linkat flags: %w", err)
		}
		argFieldValue.SetInt(int64(linkAtFlags))
	case field.TypeModuleParams:
		moduleParams, err := parseString(value)
		if err != nil {
			return nil, fmt.Errorf("cannot parse value as module params: %w", err)
		}
		argFieldValue.SetString(moduleParams)
	case field.TypeFinitModuleFlags:
		finitModuleFlags, err := parseFlags(value, finitModuleFlags)
		if err != nil {
			return nil, fmt.Errorf("cannot parse value as finit_module flags: %w", err)
		}
		argFieldValue.SetInt(int64(finitModuleFlags))
	case field.TypeDup3Flags:
		dup3Flags, err := parseFlags(value, dup3Flags)
		if err != nil {
			return nil, fmt.Errorf("cannot parse value as dup3 flags: %w", err)
		}
		argFieldValue.SetInt(int64(dup3Flags))
	case field.TypeSocketAddress:
		sockaddr, err := parseSocketAddress(value)
		if err != nil {
			return nil, fmt.Errorf("cannot parse value as socket address: %w", err)
		}
		argFieldValue.Set(reflect.ValueOf(sockaddr))
	case field.TypeSocketDomain:
		socketDomain, err := parseSingleValue(value, socketDomains)
		if err != nil {
			return nil, fmt.Errorf("cannot parse value as socket domain: %w", err)
		}
		argFieldValue.SetInt(int64(socketDomain))
	case field.TypeSocketType:
		socketType, err := parseSingleValue(value, socketTypes)
		if err != nil {
			return nil, fmt.Errorf("cannot parse value as socket type: %w", err)
		}
		argFieldValue.SetInt(int64(socketType))
	case field.TypeSocketProtocol:
		socketProtocol, err := parseSingleValue(value, socketProtocols)
		if err != nil {
			return nil, fmt.Errorf("cannot parse value as socket protocol: %w", err)
		}
		argFieldValue.SetInt(int64(socketProtocol))
	case field.TypeSendFlags:
		sendFlags, err := parseFlags(value, sendFlags)
		if err != nil {
			return nil, fmt.Errorf("cannot parse value as send flags: %w", err)
		}
		argFieldValue.SetInt(int64(sendFlags))
	case field.TypePID:
		pid, err := parseInt64(value)
		if err != nil {
			return nil, fmt.Errorf("cannot parse value as PID: %w", err)
		}
		argFieldValue.SetInt(pid)
	case field.TypeSignal:
		signal, err := parseSingleValue(value, signals)
		if err != nil {
			return nil, fmt.Errorf("cannot parse value as signal: %w", err)
		}
		argFieldValue.SetInt(int64(signal))
	case field.TypeUndefined:
		return nil, fmt.Errorf("argument field type is undefined")
	default:
		return nil, fmt.Errorf("unknown syscall argument field type %q", argFieldType)
	}

	return boundArgs, nil
}

func setSubArgFieldValues(argField *field.Field, value any) ([]string, error) {
	rawArgs, err := parseMap(value)
	if err != nil {
		return nil, fmt.Errorf("cannot parse argument field: %w", err)
	}

	boundArgs, err := setArgFieldValues(argField.Value, rawArgs)
	if err != nil {
		return nil, fmt.Errorf("error seting argument sub-fields: %w", err)
	}

	for idx := range boundArgs {
		boundArgs[idx] = field.JoinFieldPathSegments(argField.Path, boundArgs[idx])
	}
	return boundArgs, nil
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
