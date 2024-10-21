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
		fmt.Printf("%+v\n", bindings[i])

	}
	return bindings
}
