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

package base

import (
	"context"
	"fmt"
	"reflect"
	"slices"

	"github.com/falcosecurity/event-generator/pkg/test/field"
	"github.com/falcosecurity/event-generator/pkg/test/step"
)

// config is used to store syscall arguments configurations.
type config struct {
	// defaultedArgs is the list of defaulted arguments.
	defaultedArgs []string
	// mutuallyExclusiveArgsLists is the list containing lists of mutually exclusive arguments.
	mutuallyExclusiveArgsLists [][]string
	// oneRequiredArgLists is the list containing lists of arguments such that at least one argument must be specified
	// among the other arguments belonging to the same list.
	oneRequiredArgLists [][]string
	// requiredTogetherArgsLists is the list containing lists of arguments that must be specified all together if at
	// least one of them is specified.
	requiredTogetherArgsLists [][]string
}

// Option for configuring a Syscall.
type Option interface {
	apply(*config) error
}

// funcOption is an implementation of Option storing a function that implements the requested apply method behavior.
type funcOption struct {
	f func(*config) error
}

func (cfo *funcOption) apply(c *config) error {
	return cfo.f(c)
}

// newFuncOption is a helper function to create a new funcOption from a function.
func newFuncOption(f func(*config) error) *funcOption {
	return &funcOption{f: f}
}

var errArgsCannotBeEmpty = fmt.Errorf("arguments cannot be empty")

// WithDefaultedArgs allows to specify the list of defaulted arguments.
func WithDefaultedArgs(args []string) Option {
	return newFuncOption(func(c *config) error {
		if len(args) == 0 {
			return errArgsCannotBeEmpty
		}
		c.defaultedArgs = args
		return nil
	})
}

// WithMutuallyExclusiveArgs puts a constraint on the provided arguments, mandating the user to specify a value for
// at most one of them. This option can be provided multiple times to enforce mutually-exclusive-arguments constraints
// upon different arguments list.
func WithMutuallyExclusiveArgs(args []string) Option {
	return newFuncOption(func(c *config) error {
		if len(args) == 0 {
			return errArgsCannotBeEmpty
		}
		c.mutuallyExclusiveArgsLists = append(c.mutuallyExclusiveArgsLists, args)
		return nil
	})
}

// WithOneRequiredArg puts a constraint on the provided arguments, mandating the user to specify a value for at least
// one of them. This option can be provided multiple times to enforce one-required-argument constraints upon different
// arguments list.
func WithOneRequiredArg(args []string) Option {
	return newFuncOption(func(c *config) error {
		if len(args) == 0 {
			return errArgsCannotBeEmpty
		}
		c.oneRequiredArgLists = append(c.oneRequiredArgLists, args)
		return nil
	})
}

// WithRequiredTogetherArgs puts a constraint on the provided arguments, mandating the user to specify a value for each
// of them if at least a value for one of them is specified. This option can be provided multiple times to enforce
// required-together-arguments constraints upon different arguments list.
func WithRequiredTogetherArgs(args []string) Option {
	return newFuncOption(func(c *config) error {
		c.requiredTogetherArgsLists = append(c.requiredTogetherArgsLists, args)
		return nil
	})
}

// Syscall provides a common implementation layer for system call test steps.
type Syscall struct {
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
}

// New creates a new system call test step common implementation layer.
func New(stepName string, rawArgs map[string]any, fieldBindings []*step.FieldBinding, argsContainer,
	bindOnlyArgsContainer, retValueContainer reflect.Value, options ...Option) (*Syscall, error) {
	if err := checkContainersInvariants(argsContainer, bindOnlyArgsContainer, retValueContainer); err != nil {
		return nil, err
	}

	c := &config{}
	for _, opt := range options {
		if err := opt.apply(c); err != nil {
			return nil, fmt.Errorf("error applying option: %w", err)
		}
	}

	boundArgs, err := setArgFieldValues(argsContainer, rawArgs)
	if err != nil {
		return nil, fmt.Errorf("error setting argument field values: %w", err)
	}

	if err := checkArgsConstraints(c, boundArgs, fieldBindings); err != nil {
		return nil, fmt.Errorf("error checking arguments constraints: %w", err)
	}

	// Evaluate unbound arguments sets.
	unboundArgs := field.Paths(argsContainer.Type())
	for _, boundArg := range boundArgs {
		delete(unboundArgs, boundArg)
	}

	unboundBindOnlyArgs := field.Paths(bindOnlyArgsContainer.Type())

	// Remove defaulted arguments from unbound arguments sets.
	for _, arg := range c.defaultedArgs {
		delete(unboundArgs, arg)
		delete(unboundBindOnlyArgs, arg)
	}

	s := &Syscall{
		stepName:              stepName,
		argsContainer:         argsContainer,
		bindOnlyArgsContainer: bindOnlyArgsContainer,
		retValueContainer:     retValueContainer,
		unboundArgs:           unboundArgs,
		unboundBindOnlyArgs:   unboundBindOnlyArgs,
		fieldBindings:         fieldBindings,
	}
	return s, nil
}

// checkContainersInvariants verifies the requested assumptions on the provided containers.
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
			return nil, fmt.Errorf("error setting %q argument field: %w", rawArg, err)
		}

		argFieldBoundArgs, err := setArgFieldValue(argField, rawArgValue)
		if err != nil {
			return nil, fmt.Errorf("error setting %q argument field value to %v: %w", rawArg, rawArgValue, err)
		}

		boundArgs = append(boundArgs, argFieldBoundArgs...)
	}
	return boundArgs, nil
}

var errOpenModeMustBePositive = fmt.Errorf("open mode must be a positive integer")

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

// checkArgsConstraints verifies that the provided bound arguments and field bindings meet the arguments constraints
// specified by the provided config.
func checkArgsConstraints(c *config, boundArgs []string, fieldBindings []*step.FieldBinding) error {
	// Check mutually-exclusive-arguments constraints.
	for _, args := range c.mutuallyExclusiveArgsLists {
		if err := checkMutuallyExclusiveArgsConstraint(args, boundArgs, fieldBindings); err != nil {
			return fmt.Errorf("error checking mutually-exclusive-arguments constraint for %v: %w", args, err)
		}
	}

	// Check one-required-argument constraints.
	for _, args := range c.oneRequiredArgLists {
		if err := checkOneRequiredArgConstraint(args, boundArgs, fieldBindings); err != nil {
			return fmt.Errorf("error checking one-required-argument constraint for %v: %w", args, err)
		}
	}

	// Check required-together-arguments constraints.
	for _, args := range c.requiredTogetherArgsLists {
		if err := checkRequiredTogetherArgsConstraint(args, boundArgs, fieldBindings); err != nil {
			return fmt.Errorf("error checking required-together-arguments constraint for %v: %w", args, err)
		}
	}

	return nil
}

// checkMutuallyExclusiveArgsConstraint verifies that the provided bound arguments and the provided field bindings
// set/bind to at most one argument among the provided arguments. It returns an error if the condition is not met.
func checkMutuallyExclusiveArgsConstraint(args, boundArgs []string, fieldBindings []*step.FieldBinding) error {
	matchingBoundArgs, matchingFieldBindings := getArgsMatches(args, boundArgs, fieldBindings)
	if len(matchingBoundArgs)+len(matchingFieldBindings) > 1 {
		return fmt.Errorf("found %v arguments set and %v field bindings", matchingBoundArgs, matchingFieldBindings)
	}
	return nil
}

// getArgsMatches returns the sub-list of provided bound arguments and the sub-list of provided field bindings matching
// the provided arguments.
func getArgsMatches(args, boundArgs []string, fieldBindings []*step.FieldBinding) (
	matchingBoundArgs []string, matchingFieldBindings []string) {
	for _, arg := range boundArgs {
		if slices.Contains(args, arg) {
			matchingBoundArgs = append(matchingBoundArgs, arg)
		}
	}

	for _, fieldBinding := range fieldBindings {
		arg := fieldBinding.LocalField
		if slices.Contains(args, arg) {
			matchingFieldBindings = append(matchingFieldBindings, arg)
		}
	}

	return
}

var errOneRequiredArg = fmt.Errorf("at least one value must be specified for one of the arguments")

// checkOneRequiredArgConstraint verifies that the provided bound arguments and the provided field bindings set/bind to
// at least one argument among the provided arguments. It returns an error if the condition is not met.
func checkOneRequiredArgConstraint(args, boundArgs []string, fieldBindings []*step.FieldBinding) error {
	matchingBoundArgs, matchingFieldBindings := getArgsMatches(args, boundArgs, fieldBindings)
	if len(matchingBoundArgs)+len(matchingFieldBindings) == 0 {
		return errOneRequiredArg
	}
	return nil
}

// checkRequiredTogetherArgsConstraint verifies that the provided bound arguments and the provided field bindings
// set/bind to all the provided arguments if at least one of the arguments is set/bind to a value. It returns an error
// if the condition is not met.
func checkRequiredTogetherArgsConstraint(args, boundArgs []string, fieldBindings []*step.FieldBinding) error {
	matchingBoundArgs, matchingFieldBindings := getArgsMatches(args, boundArgs, fieldBindings)
	if matchesNum := len(matchingBoundArgs) + len(matchingFieldBindings); matchesNum != 0 && matchesNum != len(args) {
		return fmt.Errorf("found %v arguments set and %v field bindings", matchingBoundArgs, matchingFieldBindings)
	}
	return nil
}

// Name implements step.Step.Name method.
func (s *Syscall) Name() string {
	return s.stepName
}

// CheckUnboundArgField verifies that all argument fields are bound and returns an error in case of any unbound one.
func (s *Syscall) CheckUnboundArgField() error {
	if s.unboundArgFieldsNum() == 0 {
		return nil
	}

	unboundArgFields := s.unboundArgFieldNames()
	return fmt.Errorf("the following argument fields are not bound yet: %v", unboundArgFields)
}

// unboundArgFieldsNum returns the number of unbound argument fields.
func (s *Syscall) unboundArgFieldsNum() int {
	return len(s.unboundArgs) + len(s.unboundBindOnlyArgs)
}

// unboundArgFieldNames returns the names of the unbound argument fields.
func (s *Syscall) unboundArgFieldNames() []string {
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

// Cleanup implements step.Step.Cleanup method.
func (s *Syscall) Cleanup(_ context.Context) error {
	// No-op default implementation for syscall not needing a cleanup step.
	return nil
}

// Field implements step.Step.Field method.
func (s *Syscall) Field(name string) (*field.Field, error) {
	argFieldContainers := []reflect.Value{s.retValueContainer, s.argsContainer, s.bindOnlyArgsContainer}
	return field.ByName(name, argFieldContainers...)
}

// Bind implements step.Step.Bind method.
func (s *Syscall) Bind(bindings []*step.Binding) error {
	argFieldContainers := []reflect.Value{s.argsContainer, s.bindOnlyArgsContainer}
	return s.bindMultiple(bindings, argFieldContainers)
}

// FieldBindings implements step.Step.FieldBindings method.
func (s *Syscall) FieldBindings() []*step.FieldBinding {
	return s.fieldBindings
}

func (s *Syscall) bindMultiple(bindings []*step.Binding, argFieldContainers []reflect.Value) error {
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
