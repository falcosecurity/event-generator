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

package loader

import (
	"fmt"
	"io"
	"reflect"
	"regexp"

	"github.com/go-playground/validator/v10"
	"gopkg.in/yaml.v3"
)

// Loader loads tests configurations.
type Loader struct{}

// New creates a new Loader.
func New() *Loader {
	return &Loader{}
}

// Load loads the configuration from the provided reader.
func (l *Loader) Load(r io.Reader) (*Configuration, error) {
	dec := yaml.NewDecoder(r)
	// Force the decoding to fail if the YAML document contains unknown fields
	dec.KnownFields(true)
	conf := &Configuration{}
	if err := dec.Decode(conf); err != nil {
		return nil, fmt.Errorf("error decoding configuration: %w", err)
	}

	if err := conf.validate(); err != nil {
		return nil, fmt.Errorf("error validating configuration: %w", err)
	}

	return conf, nil
}

// Configuration contains the description of the tests.
type Configuration struct {
	Tests []Test `yaml:"tests" validate:"min=1,unique=Name"`
}

// validate validates the current configuration.
func (c *Configuration) validate() error {
	// Register custom validations and validate configuration
	validate := validator.New(validator.WithRequiredStructEnabled())
	if err := registerValidations(validate); err != nil {
		return fmt.Errorf("error registering validations: %w", err)
	}

	if err := validate.Struct(c); err != nil {
		return err
	}

	return nil
}

const validationTagRuleName = "rule_name"

var ruleNameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]{8,64}$`)

// registerValidations registers custom validations.
func registerValidations(validate *validator.Validate) error {
	if err := validate.RegisterValidation(validationTagRuleName, validateRuleName); err != nil {
		return fmt.Errorf("cannot register validation for tag %q: %w", validationTagRuleName, err)
	}

	return nil
}

// validateRuleName flags a field as valid if it matches ruleNameRegexString.
func validateRuleName(fl validator.FieldLevel) bool {
	field := fl.Field()
	if field.Kind() != reflect.String {
		return false
	}

	return ruleNameRegex.MatchString(field.String())
}

// Test is a rule test configuration.
type Test struct {
	Rule           string             `yaml:"rule" validate:"rule_name"`
	Name           string             `yaml:"name" validate:"required"`
	Description    *string            `yaml:"description" validate:"omitempty,min=1"`
	Runner         TestRunnerType     `yaml:"runner" validate:"-"`
	Context        *TestContext       `yaml:"context"`
	BeforeScript   *string            `yaml:"before" validate:"omitempty,min=1"`
	AfterScript    *string            `yaml:"after" validate:"omitempty,min=1"`
	Steps          []TestStep         `yaml:"steps" validate:"min=1,unique=Name"`
	ExpectedOutput TestExpectedOutput `yaml:"expectedOutput"`
}

// TestRunnerType is the type of test runner.
type TestRunnerType string

const (
	// TestRunnerTypeHost specifies to run the test on the host system.
	TestRunnerTypeHost TestRunnerType = "HostRunner"
)

// UnmarshalYAML populates the TestRunnerType instance by unmarshalling the content of the provided YAML node.
func (r *TestRunnerType) UnmarshalYAML(node *yaml.Node) error {
	var value string
	if err := node.Decode(&value); err != nil {
		return err
	}

	switch TestRunnerType(value) {
	case TestRunnerTypeHost:
	default:
		return fmt.Errorf("unknown test runner %q", value)
	}

	*r = TestRunnerType(value)
	return nil
}

// TestContext contains information regarding the running context of a test.
type TestContext struct {
	Container *ContainerContext `yaml:"container"`
	Processes []ProcessContext  `yaml:"processes" validate:"-"`
}

// ContainerContext contains information regarding the container instance that will run a test.
type ContainerContext struct {
	Image string  `yaml:"image" validate:"required"`
	Name  *string `yaml:"name" validate:"omitempty,min=1"`
}

// ProcessContext contains information regarding the process that will run a test, or information about one of its
// ancestors.
type ProcessContext struct {
	Name string `yaml:"name" validate:"required"`
}

// TestStep describes a test step.
type TestStep struct {
	Type          TestStepType            `yaml:"type" validate:"-"`
	Name          string                  `yaml:"name" validate:"required"`
	Spec          any                     `yaml:"-" validate:"-"`
	FieldBindings []*TestStepFieldBinding `yaml:"-" validate:"-"`
}

// UnmarshalYAML populates the TestStep instance by unmarshalling the content of the provided YAML node.
func (s *TestStep) UnmarshalYAML(node *yaml.Node) error {
	var v struct {
		Type TestStepType `yaml:"type"`
		Name string       `yaml:"name"`
	}
	if err := node.Decode(&v); err != nil {
		return err
	}

	decodedType := v.Type
	var spec any
	var fieldBindings []*TestStepFieldBinding
	switch decodedType {
	case TestStepTypeSyscall:
		var syscallSpec TestStepSyscallSpec
		if err := node.Decode(&syscallSpec); err != nil {
			return fmt.Errorf("error decoding syscall parameters: %w", err)
		}
		spec = &syscallSpec
		fieldBindings = syscallSpec.fieldBindings()
	default:
		panic(fmt.Sprintf("unknown test step type %q", decodedType))
	}

	s.Name = v.Name
	s.Type = decodedType
	s.Spec = spec
	s.FieldBindings = fieldBindings
	return nil
}

// TestStepType is the type of test step.
type TestStepType string

const (
	// TestStepTypeSyscall specifies that the test step runs a system call.
	TestStepTypeSyscall TestStepType = "syscall"
)

// UnmarshalYAML populates the TestStepType instance by unmarshalling the content of the provided YAML node.
func (t *TestStepType) UnmarshalYAML(node *yaml.Node) error {
	var value string
	if err := node.Decode(&value); err != nil {
		return err
	}

	switch TestStepType(value) {
	case TestStepTypeSyscall:
	default:
		return fmt.Errorf("unknown test step type %q", value)
	}

	*t = TestStepType(value)
	return nil
}

// TestStepSyscallSpec describes a system call test step.
type TestStepSyscallSpec struct {
	Syscall SyscallName       `yaml:"syscall" validate:"-"`
	Args    map[string]string `yaml:"args" validate:"required"`
}

// TestStepFieldBinding contains the information to perform the binding of a field belonging to a source step.
type TestStepFieldBinding struct {
	LocalField string
	SrcStep    string
	SrcField   string
}

var fieldBindingRegex = regexp.MustCompile(`^\${(.+?)\.(.+)}$`)

func (s *TestStepSyscallSpec) fieldBindings() []*TestStepFieldBinding {
	var bindings []*TestStepFieldBinding
	for arg, argValue := range s.Args {
		// Check if the user specified a field binding as value.
		match := fieldBindingRegex.FindStringSubmatch(argValue)
		if match == nil {
			continue
		}

		bindings = append(bindings, &TestStepFieldBinding{
			SrcStep:    match[1],
			SrcField:   match[2],
			LocalField: arg,
		})
		// If an argument value is a field binding, remove it from arguments.
		delete(s.Args, arg)
	}
	return bindings
}

// SyscallName represents a system call name.
type SyscallName string

const (
	// SyscallNameUndefined specifies that the system call name is not defined.
	SyscallNameUndefined SyscallName = "undefined"
	// SyscallNameWrite specifies the name of the write system call.
	SyscallNameWrite SyscallName = "write"
	// SyscallNameRead specifies the name of the read system call.
	SyscallNameRead SyscallName = "read"
	// SyscallNameOpen specifies the name of the open system call.
	SyscallNameOpen SyscallName = "open"
	// SyscallNameOpenAt specifies the name of the openat system call.
	SyscallNameOpenAt SyscallName = "openat"
	// SyscallNameOpenAt2 specifies the name of the openat2 system call.
	SyscallNameOpenAt2 SyscallName = "openat2"
)

// UnmarshalYAML populates the SyscallName instance by unmarshalling the content of the provided YAML node.
func (s *SyscallName) UnmarshalYAML(node *yaml.Node) error {
	var value string
	if err := node.Decode(&value); err != nil {
		return err
	}
	switch SyscallName(value) {
	case SyscallNameWrite:
	case SyscallNameRead:
	case SyscallNameOpen:
	case SyscallNameOpenAt:
	case SyscallNameOpenAt2:
	default:
		return fmt.Errorf("unknown syscall %q", value)
	}

	*s = SyscallName(value)
	return nil
}

// TestExpectedOutput is the expected output for a test.
type TestExpectedOutput struct {
	Source       *string           `yaml:"source" validate:"-"`
	Time         *string           `yaml:"time" validate:"-"`
	Hostname     *string           `yaml:"hostname" validate:"-"`
	Priority     *string           `yaml:"priority" validate:"-"`
	Output       *string           `yaml:"output" validate:"-"`
	OutputFields map[string]string `yaml:"outputFields" validate:"-"`
}
