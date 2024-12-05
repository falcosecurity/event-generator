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

	"github.com/go-viper/mapstructure/v2"
	"github.com/goccy/go-yaml"

	"github.com/falcosecurity/event-generator/pkg/test/loader/schema"
)

// Loader loads tests descriptions.
type Loader struct{}

// New creates a new Loader.
func New() *Loader {
	return &Loader{}
}

// Load loads the description from the provided reader.
func (l *Loader) Load(r io.Reader) (*Description, error) {
	// Decode YAML description into generic map[string]any.
	var rawDesc map[string]any

	if err := yaml.NewDecoder(r).Decode(&rawDesc); err != nil {
		return nil, fmt.Errorf("error decoding YAML description: %w", err)
	}

	// Validate generic description against schema.
	if err := schema.Validate(rawDesc); err != nil {
		return nil, fmt.Errorf("error validating YAML description: %w", err)
	}

	// Decode generic description into actual Description structure.
	desc := &Description{}
	if err := decode(rawDesc, desc, decodeTestRunnerType, decodeTestResource, decodeTestStep); err != nil {
		return nil, fmt.Errorf("error decoding description: %w", err)
	}

	if err := desc.validate(); err != nil {
		return nil, fmt.Errorf("error validating description: %w", err)
	}

	return desc, nil
}

// decode decodes the provided input into the provided output, by leveraging the provided decoding hooks.
func decode(input, output any, decodeHooks ...mapstructure.DecodeHookFunc) error {
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook: mapstructure.ComposeDecodeHookFunc(decodeHooks...),
		Result:     output,
	})
	if err != nil {
		return fmt.Errorf("error creating decoder: %w", err)
	}

	return decoder.Decode(input)
}

// decodeTestResource is a mapstructure.DecodeHookFunc allowing to unmarshal a TestResource.
func decodeTestResource(fromType, toType reflect.Type, from any) (any, error) {
	if fromType.Kind() != reflect.Map || toType != reflect.TypeOf(TestResource{}) {
		return from, nil
	}

	testResource := &TestResource{}
	if err := decode(from, testResource, decodeTestResourceType); err != nil {
		return nil, fmt.Errorf("error decoding test resource: %w", err)
	}

	decodedType := testResource.Type
	var spec any
	var decodeHooks []mapstructure.DecodeHookFunc
	switch decodedType {
	case TestResourceTypeClientServer:
		decodeHooks = append(decodeHooks, decodeTestResourceClientServerL4Proto)
		spec = &TestResourceClientServerSpec{}
	case TestResourceTypeFD:
		decodeHooks = append(decodeHooks, decodeTestResourceFDSpec)
		spec = &TestResourceFDSpec{}
	case TestResourceTypeProcess:
		spec = &TestResourceProcessSpec{}
	default:
		return nil, fmt.Errorf("unknown test resource type %q", decodedType)
	}

	if err := decode(from, spec, decodeHooks...); err != nil {
		return nil, fmt.Errorf("error decoding test resource spec: %w", err)
	}
	testResource.Spec = spec

	return testResource, nil
}

// decodeTestResourceType is a mapstructure.DecodeHookFunc allowing to unmarshal a TestResourceType.
func decodeTestResourceType(fromType, toType reflect.Type, from any) (any, error) {
	if fromType.Kind() != reflect.String || toType != reflect.TypeOf(TestResourceType("")) {
		return from, nil
	}

	switch resourceType := TestResourceType(from.(string)); resourceType {
	case TestResourceTypeClientServer, TestResourceTypeFD, TestResourceTypeProcess:
		return resourceType, nil
	default:
		return nil, fmt.Errorf("unknown test resource type %q", resourceType)
	}
}

// decodeTestResourceClientServerL4Proto is a mapstructure.DecodeHookFunc allowing to unmarshal a
// TestResourceClientServerL4Proto.
func decodeTestResourceClientServerL4Proto(fromType, toType reflect.Type, from any) (any, error) {
	if fromType.Kind() != reflect.String || toType != reflect.TypeOf(TestResourceClientServerL4Proto("")) {
		return from, nil
	}

	switch l4Proto := TestResourceClientServerL4Proto(from.(string)); l4Proto {
	case TestResourceClientServerL4ProtoUDP4, TestResourceClientServerL4ProtoUDP6, TestResourceClientServerL4ProtoTCP4,
		TestResourceClientServerL4ProtoTCP6, TestResourceClientServerL4ProtoUnix:
		return l4Proto, nil
	default:
		return nil, fmt.Errorf("unknown clientServer test resource l4 proto %q", l4Proto)
	}
}

// decodeTestResourceFDSpec is a mapstructure.DecodeHookFunc allowing to unmarshal a TestResourceFDSpec.
func decodeTestResourceFDSpec(fromType, toType reflect.Type, from any) (any, error) {
	if fromType.Kind() != reflect.Map || toType != reflect.TypeOf(TestResourceFDSpec{}) {
		return from, nil
	}

	fdSpec := &TestResourceFDSpec{}
	if err := decode(from, fdSpec, decodeTestResourceFDSubtype); err != nil {
		return nil, fmt.Errorf("error decoding fd test resource spec: %w", err)
	}

	decodedSubtype := fdSpec.Subtype
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
		return nil, fmt.Errorf("unknown fd test resource subtype %q", decodedSubtype)
	}

	if err := decode(from, spec); err != nil {
		return nil, fmt.Errorf("error decoding fd test resource subtype spec: %w", err)
	}

	fdSpec.Spec = spec
	return fdSpec, nil
}

// decodeTestResourceFDSubtype is a mapstructure.DecodeHookFunc allowing to unmarshal a TestResourceFDSubtype.
func decodeTestResourceFDSubtype(fromType, toType reflect.Type, from any) (any, error) {
	if fromType.Kind() != reflect.Map || toType != reflect.TypeOf(TestResourceFDSubtype("")) {
		return from, nil
	}

	switch subtype := TestResourceFDSubtype(from.(string)); subtype {
	case TestResourceFDSubtypeFile, TestResourceFDSubtypeDirectory, TestResourceFDSubtypePipe,
		TestResourceFDSubtypeEvent, TestResourceFDSubtypeSignal, TestResourceFDSubtypeEpoll,
		TestResourceFDSubtypeInotify, TestResourceFDSubtypeMem:
		return subtype, nil
	default:
		return nil, fmt.Errorf("unknown fd test resource subtype %q", subtype)
	}
}

// decodeTestStep is a mapstructure.DecodeHookFunc allowing to unmarshal a TestStep.
func decodeTestStep(fromType, toType reflect.Type, from any) (any, error) {
	if fromType.Kind() != reflect.Map || toType != reflect.TypeOf(TestStep{}) {
		return from, nil
	}

	testStep := &TestStep{}
	if err := decode(from, testStep, decodeTestStepType); err != nil {
		return nil, fmt.Errorf("error decoding test step: %w", err)
	}

	decodedType := testStep.Type
	var spec any
	var fieldBindings []*TestStepFieldBinding
	switch decodedType {
	case TestStepTypeSyscall:
		var syscallSpec TestStepSyscallSpec
		if err := decode(from, &syscallSpec, decodeTestStepSyscallName); err != nil {
			return nil, fmt.Errorf("error decoding syscaòò test step spec: %w", err)
		}

		spec = &syscallSpec
		fieldBindings = getFieldBindings("", syscallSpec.Args)
	default:
		return nil, fmt.Errorf("unknown test step type %q", decodedType)
	}

	testStep.Spec = spec
	testStep.FieldBindings = fieldBindings
	return testStep, nil
}

var fieldBindingRegex = regexp.MustCompile(`^\${(.+?)\.(.+)}$`)

// getFieldBindings returns the field bindings found in the provided arguments.
func getFieldBindings(containingArgName string, args map[string]any) []*TestStepFieldBinding {
	// The prefix of each contained argument is composed by the containing argument name.
	var argsPrefix string
	if containingArgName != "" {
		argsPrefix = containingArgName + "."
	}

	var bindings []*TestStepFieldBinding
	for arg, argValue := range args {
		switch argValue := argValue.(type) {
		case string:
			// Check if the user specified a field binding as value.
			match := fieldBindingRegex.FindStringSubmatch(argValue)
			if match == nil {
				continue
			}

			bindings = append(bindings, &TestStepFieldBinding{
				SrcStep:    match[1],
				SrcField:   match[2],
				LocalField: argsPrefix + arg,
			})

			// If an argument value is a field binding, remove it from arguments.
			delete(args, arg)
		case map[string]any:
			bindings = append(bindings, getFieldBindings(arg, argValue)...)
		}
	}
	return bindings
}

// decodeTestStepType is a mapstructure.DecodeHookFunc allowing to unmarshal a TestStepType.
func decodeTestStepType(fromType, toType reflect.Type, from any) (any, error) {
	if fromType.Kind() != reflect.Map || toType != reflect.TypeOf(TestStepType("")) {
		return from, nil
	}

	switch stepType := TestStepType(from.(string)); stepType {
	case TestStepTypeSyscall:
		return stepType, nil
	default:
		return nil, fmt.Errorf("unknown test step type %q", stepType)
	}
}

// decodeTestRunnerType is a mapstructure.DecodeHookFunc allowing to unmarshal a TestRunnerType.
func decodeTestRunnerType(fromType, toType reflect.Type, from any) (any, error) {
	if fromType.Kind() != reflect.String || toType != reflect.TypeOf(TestRunnerType("")) {
		return from, nil
	}

	switch runnerType := TestRunnerType(from.(string)); runnerType {
	case TestRunnerTypeHost:
		return runnerType, nil
	default:
		return nil, fmt.Errorf("unknown test runner %q", runnerType)
	}
}

// decodeTestStepSyscallName is a mapstructure.DecodeHookFunc allowing to unmarshal a SyscallName.
func decodeTestStepSyscallName(fromType, toType reflect.Type, from any) (any, error) {
	if fromType.Kind() != reflect.String || toType != reflect.TypeOf(SyscallName("")) {
		return from, nil
	}

	switch syscallName := SyscallName(from.(string)); syscallName {
	case SyscallNameWrite, SyscallNameRead, SyscallNameOpen, SyscallNameOpenAt, SyscallNameOpenAt2, SyscallNameSymLink,
		SyscallNameSymLinkAt, SyscallNameLink, SyscallNameLinkAt, SyscallNameInitModule, SyscallNameFinitModule,
		SyscallNameDup, SyscallNameDup2, SyscallNameDup3, SyscallNameConnect, SyscallNameSocket, SyscallNameSendTo,
		SyscallNameKill:
		return syscallName, nil
	default:
		return nil, fmt.Errorf("unknown syscall %q", syscallName)
	}
}

// Description contains the description of the tests.
type Description struct {
	Tests []Test `yaml:"tests" mapstructure:"tests"`
}

// Write writes the description to the provided writer.
func (c *Description) Write(w io.Writer) error {
	enc := yaml.NewEncoder(w)
	if err := enc.Encode(c); err != nil {
		return fmt.Errorf("error encoding description: %w", err)
	}

	return nil
}

// validate validates the current description.
func (c *Description) validate() error {
	for testIndex := range c.Tests {
		test := &c.Tests[testIndex]
		if err := test.validateNameUniqueness(); err != nil {
			return fmt.Errorf("error validating name uniqueness in test %q (index: %d): %w", test.Name,
				testIndex, err)
		}

		if err := test.validateContext(); err != nil {
			return fmt.Errorf("error validating test context: %w", err)
		}
	}

	return nil
}

// Test is a rule test description.
type Test struct {
	Rule            string              `yaml:"rule" mapstructure:"rule"`
	Name            string              `yaml:"name" mapstructure:"name"`
	Description     *string             `yaml:"description,omitempty" mapstructure:"description"`
	Runner          TestRunnerType      `yaml:"runner" mapstructure:"runner"`
	Context         *TestContext        `yaml:"context,omitempty" mapstructure:"context"`
	BeforeScript    *string             `yaml:"before,omitempty" mapstructure:"before"`
	AfterScript     *string             `yaml:"after,omitempty" mapstructure:"after"`
	Resources       []TestResource      `yaml:"resources,omitempty" mapstructure:"resources"`
	Steps           []TestStep          `yaml:"steps,omitempty" mapstructure:"steps"`
	ExpectedOutcome TestExpectedOutcome `yaml:"expectedOutcome" mapstructure:"expectedOutcome"`
}

// validateNameUniqueness validates that names used for test resources and steps are unique.
func (t *Test) validateNameUniqueness() error {
	for resourceIndex, testResource := range t.Resources {
		for stepIndex, testStep := range t.Steps {
			if testStep.Name == testResource.Name {
				return fmt.Errorf("test resource at index %d and test step at index %d have the same name %q",
					resourceIndex, stepIndex, testResource.Name)
			}
		}
	}
	return nil
}

// validateContext validates that names used for test resources and steps are unique.
func (t *Test) validateContext() error {
	if t.Context == nil {
		return nil
	}

	processes := t.Context.Processes
	processesLen := len(processes)
	if processesLen <= 1 {
		return nil
	}

	for processIndex, process := range processes[:processesLen-1] {
		if process.Capabilities != nil && *process.Capabilities != "" {
			return fmt.Errorf("process at index %d specifies capabilities but is not the leaf process", processIndex)
		}
	}
	return nil
}

// TestRunnerType is the type of test runner.
type TestRunnerType string

const (
	// TestRunnerTypeHost specifies to run the test on the host system.
	TestRunnerTypeHost TestRunnerType = "HostRunner"
)

// TestContext contains information regarding the running context of a test.
type TestContext struct {
	Container *ContainerContext `yaml:"container,omitempty" mapstructure:"container"`
	Processes []ProcessContext  `yaml:"processes,omitempty" mapstructure:"processes"`
}

// ContainerContext contains information regarding the container instance that will run a test.
type ContainerContext struct {
	// Image is the name the base event-generator image must be tagged with before being used to spawn the container. If
	// omitted, it defaults to the name of the base event-generator image.
	Image *string `yaml:"image" mapstructure:"image"`
	// Name is the name that must be used to identify the container. If omitted, it defaults to "event-generator".
	Name *string `yaml:"name,omitempty" mapstructure:"name"`
	// Env is the set of environment variables that must be provided to the container (in addition to the default ones).
	Env map[string]string `yaml:"env,omitempty" mapstructure:"env"`
}

// ProcessContext contains information regarding the process that will run a test, or information about one of its
// ancestors.
type ProcessContext struct {
	// ExePath is the executable path. If omitted, it is randomly generated.
	ExePath *string `yaml:"exePath,omitempty" mapstructure:"exePath"`
	// Args is a string containing the space-separated list of command line arguments. If a single argument contains
	// spaces, the entire argument must be quoted in order to not be considered as multiple arguments. If omitted, it
	// defaults to "".
	Args *string `yaml:"args,omitempty" mapstructure:"args"`
	// Exe is the argument in position 0 (a.k.a. argv[0]) of the process. If omitted, it defaults to Name if this is
	// specified; otherwise, it defaults to filepath.Base(ExePath).
	Exe *string `yaml:"exe,omitempty" mapstructure:"exe"`
	// Name is the process name. If omitted, it defaults to filepath.Base(ExePath).
	Name *string `yaml:"name,omitempty" mapstructure:"name"`
	// Env is the set of environment variables that must be provided to the process (in addition to the default ones).
	Env map[string]string `yaml:"env,omitempty" mapstructure:"env"`
	// User is the name of the user that must run the process. If omitted, the current process user is used. If the user
	// does not exist, it is created before running the test and deleted after test execution.
	User *string `yaml:"user,omitempty" mapstructure:"user"`
	// Capabilities are the capabilities of the process. The syntax follows the conventions specified by
	// cap_from_text(3). If omitted or empty, it defaults to "all=iep".
	Capabilities *string `yaml:"capabilities,omitempty" mapstructure:"capabilities"`
}

// TestResource describes a test resource.
type TestResource struct {
	Type TestResourceType `yaml:"type" mapstructure:"type"`
	Name string           `yaml:"name" mapstructure:"name"`
	Spec any              `yaml:"spec,inline" mapstructure:"-"`
}

// TestResourceType is the type of test resource.
type TestResourceType string

const (
	// TestResourceTypeClientServer specifies that the resource runs a client and a server.
	TestResourceTypeClientServer TestResourceType = "clientServer"
	// TestResourceTypeFD specifies that the resource creates a file descriptor.
	TestResourceTypeFD TestResourceType = "fd"
	// TestResourceTypeProcess specifies that the resource creates a process.
	TestResourceTypeProcess TestResourceType = "process"
)

// TestResourceClientServerSpec describes a clientServer test resource.
type TestResourceClientServerSpec struct {
	L4Proto TestResourceClientServerL4Proto `yaml:"l4Proto" mapstructure:"l4Proto"`
	Address string                          `yaml:"address" mapstructure:"address"`
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

// TestResourceFDSpec describes an fd test resource.
type TestResourceFDSpec struct {
	Subtype TestResourceFDSubtype `yaml:"subtype" mapstructure:"subtype"`
	Spec    any                   `yaml:"spec,inline" mapstructure:"-"`
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

// TestResourceFDFileSpec describes a regular file fd test resource.
type TestResourceFDFileSpec struct {
	FilePath string `yaml:"filePath" mapstructure:"filePath"`
}

// TestResourceFDDirectorySpec describes a directory fd test resource.
type TestResourceFDDirectorySpec struct {
	DirPath string `yaml:"dirPath" mapstructure:"dirPath"`
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
	FileName string `yaml:"fileName" mapstructure:"fileName"`
}

// TestResourceProcessSpec describes a process test resource.
type TestResourceProcessSpec struct {
	// ExePath is the executable path. If omitted, it is randomly generated.
	ExePath *string `yaml:"exePath,omitempty" mapstructure:"exePath"`
	// Args is a string containing the space-separated list of command line arguments. If a single argument contains
	// spaces, the entire argument must be quoted in order to not be considered as multiple arguments. If omitted, it
	// defaults to "".
	Args *string `yaml:"args,omitempty" mapstructure:"args"`
	// Exe is the argument in position 0 (a.k.a. argv[0]) of the process. If omitted, it defaults to Name if this is
	// specified; otherwise, it defaults to filepath.Base(ExePath).
	Exe *string `yaml:"exe,omitempty" mapstructure:"exe"`
	// Name is the process name. If omitted, it defaults to filepath.Base(ExePath).
	Name *string `yaml:"procName,omitempty" mapstructure:"procName"`
	// Env is the set of environment variables that must be provided to the process (in addition to the default ones).
	Env map[string]string `yaml:"env,omitempty" mapstructure:"env"`
}

// TestStep describes a test step.
type TestStep struct {
	Type          TestStepType            `yaml:"type" mapstructure:"type"`
	Name          string                  `yaml:"name" mapstructure:"name"`
	Spec          any                     `yaml:"-" mapstructure:"-"`
	FieldBindings []*TestStepFieldBinding `yaml:"-" mapstructure:"-"`
}

// MarshalYAML returns an inner representation of the TestStep instance that is used, in place of the instance, to
// marshal the content.
func (s TestStep) MarshalYAML() (any, error) {
	switch stepType := s.Type; stepType {
	case TestStepTypeSyscall:
		spec := s.Spec.(*TestStepSyscallSpec)
		args := make(map[string]any, len(spec.Args)+len(s.FieldBindings))
		for arg, argValue := range spec.Args {
			args[arg] = argValue
		}
		for _, fieldBinding := range s.FieldBindings {
			args[fieldBinding.LocalField] = fmt.Sprintf("${%s.%s}", fieldBinding.SrcStep, fieldBinding.SrcField)
		}
		return struct {
			Type TestStepType         `yaml:"type"`
			Name string               `yaml:"name"`
			Spec *TestStepSyscallSpec `yaml:"spec,inline"`
		}{Type: stepType, Name: s.Name, Spec: &TestStepSyscallSpec{Syscall: spec.Syscall, Args: args}}, nil
	default:
		return nil, fmt.Errorf("unknown test step type %q", stepType)
	}
}

// TestStepType is the type of test step.
type TestStepType string

const (
	// TestStepTypeSyscall specifies that the test step runs a system call.
	TestStepTypeSyscall TestStepType = "syscall"
)

// TestStepSyscallSpec describes a system call test step.
type TestStepSyscallSpec struct {
	Syscall SyscallName    `yaml:"syscall" mapstructure:"syscall"`
	Args    map[string]any `yaml:"args" mapstructure:"args"`
}

// SyscallName represents a system call name.
type SyscallName string

const (
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
	// SyscallNameKill specifies the name of the kill system call.
	SyscallNameKill SyscallName = "kill"
)

// TestStepFieldBinding contains the information to perform the binding of a field belonging to a source step.
type TestStepFieldBinding struct {
	LocalField string
	SrcStep    string
	SrcField   string
}

// TestExpectedOutcome is the expected outcome for a test.
type TestExpectedOutcome struct {
	Source       *string           `yaml:"source,omitempty" mapstructure:"source"`
	Hostname     *string           `yaml:"hostname,omitempty" mapstructure:"hostname"`
	Priority     *string           `yaml:"priority,omitempty" mapstructure:"priority"`
	OutputFields map[string]string `yaml:"outputFields,omitempty" mapstructure:"outputFields"`
}
