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
	Tests []Test `yaml:"tests" validate:"min=1,unique=Name,dive"`
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

	for testIndex := range c.Tests {
		test := &c.Tests[testIndex]
		if err := validateNameUniqueness(test); err != nil {
			return fmt.Errorf("error validating name uniqueness in test %q (index: %d): %w", test.Name,
				testIndex, err)
		}
	}

	return nil
}

// validateNameUniqueness validates that names used for test resources and steps are unique.
func validateNameUniqueness(test *Test) error {
	for resourceIndex, testResource := range test.Resources {
		for stepIndex, testStep := range test.Steps {
			if testStep.Name == testResource.Name {
				return fmt.Errorf("test resource %d and test step %d have the same name %q", resourceIndex,
					stepIndex, testResource.Name)
			}
		}
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
	Resources      []TestResource     `yaml:"resources" validate:"omitempty,unique=Name,dive"`
	Steps          []TestStep         `yaml:"steps" validate:"min=1,unique=Name,dive"`
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

// TestResource describes a test resource.
type TestResource struct {
	Type TestResourceType `yaml:"type" validate:"-"`
	Name string           `yaml:"name" validate:"required"`
	Spec any              `yaml:"-"`
}

// UnmarshalYAML populates the TestResource instance by unmarshalling the content of the provided YAML node.
func (r *TestResource) UnmarshalYAML(node *yaml.Node) error {
	var v struct {
		Type TestResourceType `yaml:"type"`
		Name string           `yaml:"name"`
	}
	if err := node.Decode(&v); err != nil {
		return err
	}

	decodedType := v.Type
	var spec any
	switch decodedType {
	case TestResourceTypeClientServer:
		spec = &TestResourceClientServerSpec{}
	case TestResourceTypeFD:
		spec = &TestResourceFDSpec{}
	default:
		panic(fmt.Sprintf("unknown test resource type %q", decodedType))
	}

	if err := node.Decode(spec); err != nil {
		return fmt.Errorf("error decoding clientServer test resource spec: %w", err)
	}

	r.Name = v.Name
	r.Type = decodedType
	r.Spec = spec
	return nil
}

// TestResourceType is the type of test resource.
type TestResourceType string

const (
	// TestResourceTypeClientServer specifies that the resource runs a client and a server.
	TestResourceTypeClientServer TestResourceType = "clientServer"
	// TestResourceTypeFD specifies that the resource creates a file descriptor.
	TestResourceTypeFD TestResourceType = "fd"
)

// UnmarshalYAML populates the TestResourceType instance by unmarshalling the content of the provided YAML node.
func (t *TestResourceType) UnmarshalYAML(node *yaml.Node) error {
	var value string
	if err := node.Decode(&value); err != nil {
		return err
	}

	switch TestResourceType(value) {
	case TestResourceTypeClientServer:
	case TestResourceTypeFD:
	default:
		return fmt.Errorf("unknown test step type %q", value)
	}

	*t = TestResourceType(value)
	return nil
}

// TestResourceClientServerSpec describes a clientServer test resource.
type TestResourceClientServerSpec struct {
	L4Proto TestResourceClientServerL4Proto `yaml:"l4Proto" validate:"-"`
	Address string                          `yaml:"address" validate:"required"`
}

// TestResourceClientServerL4Proto is the transport protocol used by the clientServer test resource client and the
// server.
type TestResourceClientServerL4Proto string

const (
	// TestResourceClientServerL4ProtoUDP4 specifies that the clientServer test resource will use UDP over IPv4 to
	// implement the communication between client and server.
	TestResourceClientServerL4ProtoUDP4 TestResourceClientServerL4Proto = "udp4"
	// TestResourceClientServerL4ProtoUDP6 specifies that the clientServer test resource will use UDP over IPv6 to
	// implement the communication between client and server.
	TestResourceClientServerL4ProtoUDP6 TestResourceClientServerL4Proto = "udp6"
	// TestResourceClientServerL4ProtoTCP4 specifies that the clientServer test resource will use TCP over IPv4 to
	// implement the communication between client and server.
	TestResourceClientServerL4ProtoTCP4 TestResourceClientServerL4Proto = "tcp4"
	// TestResourceClientServerL4ProtoTCP6 specifies that the clientServer test resource will use TCP over IPv6 to
	// implement the communication between client and server.
	TestResourceClientServerL4ProtoTCP6 TestResourceClientServerL4Proto = "tcp6"
	// TestResourceClientServerL4ProtoUnix specifies that the clientServer test resource will use Unix sockets to
	// implement the communication between client and server.
	TestResourceClientServerL4ProtoUnix TestResourceClientServerL4Proto = "unix"
)

// UnmarshalYAML populates the TestResourceClientServerL4Proto instance by unmarshalling the content of the provided
// YAML node.
func (t *TestResourceClientServerL4Proto) UnmarshalYAML(node *yaml.Node) error {
	var value string
	if err := node.Decode(&value); err != nil {
		return err
	}

	switch TestResourceClientServerL4Proto(value) {
	case TestResourceClientServerL4ProtoUDP4:
	case TestResourceClientServerL4ProtoUDP6:
	case TestResourceClientServerL4ProtoTCP4:
	case TestResourceClientServerL4ProtoTCP6:
	case TestResourceClientServerL4ProtoUnix:
	default:
		return fmt.Errorf("unknown clientServer test resource l4 proto %q", value)
	}

	*t = TestResourceClientServerL4Proto(value)
	return nil
}

// TestResourceFDSpec describes an fd test resource.
type TestResourceFDSpec struct {
	Subtype TestResourceFDSubtype `yaml:"subtype" validate:"-"`
	Spec    any                   `yaml:"-"`
}

// UnmarshalYAML populates the TestResourceFDSpec instance by unmarshalling the content of the provided YAML node.
func (s *TestResourceFDSpec) UnmarshalYAML(node *yaml.Node) error {
	var v struct {
		Subtype TestResourceFDSubtype `yaml:"subtype"`
	}
	if err := node.Decode(&v); err != nil {
		return err
	}

	decodedSubtype := v.Subtype
	var spec any
	switch decodedSubtype {
	case TestResourceFDSubtypeFile:
		spec = &TestResourceFDFileSpec{}
	case TestResourceFDSubtypeDirectory:
		spec = &TestResourceFDDirectorySpec{}
	case TestResourceFDSubtypePipe:
		spec = &TestResourceFDPipeSpec{}
	case TestResourceFDSubtypeEvent:
		spec = &TestResourceFDEventSpec{}
	case TestResourceFDSubtypeSignal:
		spec = &TestResourceFDSignalSpec{}
	case TestResourceFDSubtypeEpoll:
		spec = &TestResourceFDEpollSpec{}
	case TestResourceFDSubtypeInotify:
		spec = &TestResourceFDInotifySpec{}
	case TestResourceFDSubtypeMem:
		spec = &TestResourceFDMemSpec{}
	default:
		panic(fmt.Sprintf("unknown fd test resource subtype %q", decodedSubtype))
	}

	if err := node.Decode(spec); err != nil {
		return fmt.Errorf("error decoding fd test resource %s spec: %w", decodedSubtype, err)
	}

	s.Subtype = decodedSubtype
	s.Spec = spec
	return nil
}

// TestResourceFDSubtype is the subtype of fd test resource.
type TestResourceFDSubtype string

const (
	// TestResourceFDSubtypeFile specifies to create a file descriptor referring to a regular file.
	TestResourceFDSubtypeFile TestResourceFDSubtype = "file"
	// TestResourceFDSubtypeDirectory specifies to create a file descriptor referring to a directory.
	TestResourceFDSubtypeDirectory TestResourceFDSubtype = "directory"
	// TestResourceFDSubtypePipe specifies to create a "read" and "write" file descriptor referring to the ends of a
	// pipe.
	TestResourceFDSubtypePipe TestResourceFDSubtype = "pipe"
	// TestResourceFDSubtypeEvent specifies to create an event file descriptor.
	TestResourceFDSubtypeEvent TestResourceFDSubtype = "event"
	// TestResourceFDSubtypeSignal specifies to create a signal file descriptor.
	TestResourceFDSubtypeSignal TestResourceFDSubtype = "signalfd"
	// TestResourceFDSubtypeEpoll specifies to create an epoll file descriptor.
	TestResourceFDSubtypeEpoll TestResourceFDSubtype = "eventpoll"
	// TestResourceFDSubtypeInotify specifies to create an inotify file descriptor.
	TestResourceFDSubtypeInotify TestResourceFDSubtype = "inotify"
	// TestResourceFDSubtypeMem specifies to create a mem file descriptor.
	TestResourceFDSubtypeMem TestResourceFDSubtype = "memfd"
)

// UnmarshalYAML populates the TestResourceFDSubtype instance by unmarshalling the content of the provided YAML node.
func (t *TestResourceFDSubtype) UnmarshalYAML(node *yaml.Node) error {
	var value string
	if err := node.Decode(&value); err != nil {
		return err
	}

	switch TestResourceFDSubtype(value) {
	case TestResourceFDSubtypeFile:
	case TestResourceFDSubtypeDirectory:
	case TestResourceFDSubtypePipe:
	case TestResourceFDSubtypeEvent:
	case TestResourceFDSubtypeSignal:
	case TestResourceFDSubtypeEpoll:
	case TestResourceFDSubtypeInotify:
	case TestResourceFDSubtypeMem:
	default:
		return fmt.Errorf("unknown fd test resource subtype %q", value)
	}

	*t = TestResourceFDSubtype(value)
	return nil
}

// TestResourceFDFileSpec describes a regular file fd test resource.
type TestResourceFDFileSpec struct {
	FilePath string `yaml:"filePath" validate:"required"`
}

// TestResourceFDDirectorySpec describes a directory fd test resource.
type TestResourceFDDirectorySpec struct {
	DirPath string `yaml:"dirPath" validate:"required"`
}

// TestResourceFDPipeSpec describes a pipe fd test resource.
type TestResourceFDPipeSpec struct{}

// TestResourceFDEventSpec describes an event fd test resource.
type TestResourceFDEventSpec struct{}

// TestResourceFDSignalSpec describes a signal fd test resource.
type TestResourceFDSignalSpec struct{}

// TestResourceFDEpollSpec describes an epoll fd test resource.
type TestResourceFDEpollSpec struct{}

// TestResourceFDInotifySpec describes an inotify fd test resource.
type TestResourceFDInotifySpec struct{}

// TestResourceFDMemSpec describes a mem fd test resource.
type TestResourceFDMemSpec struct {
	FileName string `yaml:"fileName" validate:"required"`
}

// TestStep describes a test step.
type TestStep struct {
	Type          TestStepType            `yaml:"type" validate:"-"`
	Name          string                  `yaml:"name" validate:"required"`
	Spec          any                     `yaml:"-"`
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
	// SyscallNameSymLink specifies the name of the symlink system call.
	SyscallNameSymLink SyscallName = "symlink"
	// SyscallNameSymLinkAt specifies the name of the symlinkat system call.
	SyscallNameSymLinkAt SyscallName = "symlinkat"
	// SyscallNameLink specifies the name of the link system call.
	SyscallNameLink SyscallName = "link"
	// SyscallNameLinkAt specifies the name of the linkat system call.
	SyscallNameLinkAt SyscallName = "linkat"
	// SyscallNameInitModule specifies the name of the init_module system call.
	SyscallNameInitModule SyscallName = "init_module"
	// SyscallNameFinitModule specifies the name of the finit_module system call.
	SyscallNameFinitModule SyscallName = "finit_module"
	// SyscallNameDup specifies the name of the dup system call.
	SyscallNameDup SyscallName = "dup"
	// SyscallNameDup2 specifies the name of the dup2 system call.
	SyscallNameDup2 SyscallName = "dup2"
	// SyscallNameDup3 specifies the name of the dup3 system call.
	SyscallNameDup3 SyscallName = "dup3"
	// SyscallNameConnect specifies the name of the connect system call.
	SyscallNameConnect SyscallName = "connect"
	// SyscallNameSocket specifies the name of the socket system call.
	SyscallNameSocket SyscallName = "socket"
	// SyscallNameSendTo specifies the name of the sendto system call.
	SyscallNameSendTo SyscallName = "sendto"
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
	case SyscallNameSymLink:
	case SyscallNameSymLinkAt:
	case SyscallNameLink:
	case SyscallNameLinkAt:
	case SyscallNameInitModule:
	case SyscallNameFinitModule:
	case SyscallNameDup:
	case SyscallNameDup2:
	case SyscallNameDup3:
	case SyscallNameConnect:
	case SyscallNameSocket:
	case SyscallNameSendTo:
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
