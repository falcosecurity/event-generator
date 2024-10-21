package initmodule

import (
	"context"
	"github.com/falcosecurity/event-generator/pkg/test/step"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/base"
	"golang.org/x/sys/unix"
	"reflect"
)

type initModuleSyscall struct {
	// args represents arguments that can be provided by value or by binding.
	args struct {
		ModuleImage []byte `field_type:"buffer"`
		ParamValues string `field_type:"module_params"`
	}
	// bindOnlyArgs represents arguments that can only be provided by binding.
	bindOnlyArgs struct{}
	Ret          int
}

// New creates a new init_module system call test step.
func New(name string, rawArgs map[string]string,
	fieldBindings []*step.FieldBinding) (syscall.Syscall, error) {
	i := &initModuleSyscall{}
	// i.args.ParamValues defaulted to ""
	argsContainer := reflect.ValueOf(&i.args).Elem()
	bindOnlyArgsContainer := reflect.ValueOf(&i.bindOnlyArgs).Elem()
	retValContainer := reflect.ValueOf(i).Elem()
	defaultedArgs := []string{"paramvalues"}
	return base.New(name, rawArgs, fieldBindings, argsContainer, bindOnlyArgsContainer, retValContainer, defaultedArgs,
		i.run, nil)
}

func (i *initModuleSyscall) run(_ context.Context) error {
	if err := unix.InitModule(i.args.ModuleImage, i.args.ParamValues); err != nil {
		return err
	}

	return nil
}
