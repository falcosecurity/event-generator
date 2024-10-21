package finitmodule

import (
	"context"
	"github.com/falcosecurity/event-generator/pkg/test/step"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/base"
	"golang.org/x/sys/unix"
	"reflect"
)

type finitModuleSyscall struct {
	// args represents arguments that can be provided by value or by binding.
	args struct {
		ParamValues string `field_type:"module_params"`
		Flags       int    `field_type:"finit_module_flags"`
	}
	// bindOnlyArgs represents arguments that can only be provided by binding.
	bindOnlyArgs struct {
		FD int `field_type:"fd"`
	}
	Ret int
}

// New creates a new finit_module system call test step.
func New(name string, rawArgs map[string]string,
	fieldBindings []*step.FieldBinding) (syscall.Syscall, error) {
	f := &finitModuleSyscall{}
	// f.args.ParamValues defaulted to ""
	// f.args.Flags defaulted to 0
	argsContainer := reflect.ValueOf(&f.args).Elem()
	bindOnlyArgsContainer := reflect.ValueOf(&f.bindOnlyArgs).Elem()
	retValContainer := reflect.ValueOf(f).Elem()
	defaultedArgs := []string{"paramvalues", "flags"}
	return base.New(name, rawArgs, fieldBindings, argsContainer, bindOnlyArgsContainer, retValContainer, defaultedArgs,
		f.run, nil)
}

func (f *finitModuleSyscall) run(_ context.Context) error {
	if err := unix.FinitModule(f.bindOnlyArgs.FD, f.args.ParamValues, f.args.Flags); err != nil {
		return err
	}

	return nil
}
