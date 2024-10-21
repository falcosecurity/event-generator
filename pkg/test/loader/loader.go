package loader

import (
	"fmt"
	"github.com/go-playground/validator/v10"
	"gopkg.in/yaml.v3"
	"io"
	"reflect"
	"regexp"
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
		return nil, fmt.Errorf("error decoding configuration: %v", err)
	}

	if err := conf.validate(); err != nil {
		return nil, fmt.Errorf("error validating configuration: %v", err)
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
	validate := validator.New()
	validator.WithRequiredStructEnabled()
	if err := registerValidations(validate); err != nil {
		return fmt.Errorf("error registering validations: %v", err)
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
		return fmt.Errorf("cannot register validation for tag %q: %v", validationTagRuleName, err)
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

type TestRunnerType string

const (
	TestRunnerTypeHost      TestRunnerType = "HostRunner"
	TestRunnerTypeContainer TestRunnerType = "ContainerRunner"
)

func (r *TestRunnerType) UnmarshalYAML(node *yaml.Node) error {
	var value string
	if err := node.Decode(&value); err != nil {
		return err
	}

	switch TestRunnerType(value) {
	case TestRunnerTypeHost:
	case TestRunnerTypeContainer:
	default:
		return fmt.Errorf("unknown test runner %q", value)
	}

	*r = TestRunnerType(value)
	return nil
}

type TestContext struct {
	Container *ContainerContext `yaml:"container"`
	Processes []ProcessContext  `yaml:"processes" validate:"-"`
}

type ContainerContext struct {
	Image string  `yaml:"image" validate:"required"`
	Name  *string `yaml:"name" validate:"omitempty,min=1"`
}

type ProcessContext struct {
	Name string `yaml:"name" validate:"required"`
}

type TestStep struct {
	Type          TestStepType            `yaml:"type" validate:"-"`
	Name          string                  `yaml:"name" validate:"required"`
	Spec          any                     `yaml:"-" validate:"-"`
	FieldBindings []*TestStepFieldBinding `yaml:"-" validate:"-"`
}

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
			return fmt.Errorf("error decoding syscall parameters: %v", err)
		}
		syscallBindings, err := syscallSpec.fieldBindings()
		if err != nil {
			return err
		}
		spec = &syscallSpec
		fieldBindings = syscallBindings
	default:
		panic(fmt.Sprintf("unknown test step type %q", decodedType))
	}

	s.Name = v.Name
	s.Type = decodedType
	s.Spec = spec
	s.FieldBindings = fieldBindings
	return nil
}

type TestStepType string

const (
	TestStepTypeSyscall TestStepType = "syscall"
)

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

type TestStepSyscallSpec struct {
	Syscall SyscallName       `yaml:"syscall" validate:"-"`
	Args    map[string]string `yaml:"args" validate:"required"`
}

type TestStepFieldBinding struct {
	LocalField string
	SrcStep    string
	SrcField   string
}

var fieldBindingRegex = regexp.MustCompile(`^\${(.+?)\.(.+)}$`)

func (s *TestStepSyscallSpec) fieldBindings() ([]*TestStepFieldBinding, error) {
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
	return bindings, nil
}

type SyscallName string

const (
	SyscallNameWrite SyscallName = "write"
)

func (s *SyscallName) UnmarshalYAML(node *yaml.Node) error {
	var value string
	if err := node.Decode(&value); err != nil {
		return err
	}
	switch SyscallName(value) {
	case SyscallNameWrite:
	default:
		return fmt.Errorf("unknown syscall %q", value)
	}

	*s = SyscallName(value)
	return nil
}

type TestExpectedOutput struct {
	Source       *string           `yaml:"source" validate:"-"`
	Time         *string           `yaml:"time" validate:"-"`
	Hostname     *string           `yaml:"hostname" validate:"-"`
	Priority     *string           `yaml:"priority" validate:"-"`
	Output       *string           `yaml:"output" validate:"-"`
	OutputFields map[string]string `yaml:"outputFields" validate:"-"`
}
