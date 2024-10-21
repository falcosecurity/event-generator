package connect

import (
	"context"
	"github.com/falcosecurity/event-generator/pkg/test/step"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/base"
	"golang.org/x/sys/unix"
	"reflect"
)

type connectSyscall struct {
	// args represents arguments that can be provided by value or by binding.
	args struct {
		FD      int           `field_type:"fd"`
		Address unix.Sockaddr `field_type:"socket_address"`
	}
	// bindOnlyArgs represents arguments that can only be provided by binding.
	bindOnlyArgs struct{}
	Ret          int `field_type:"-"`
}

// New creates a new connect system call test step.
func New(name string, rawArgs map[string]string,
	fieldBindings []*step.FieldBinding) (syscall.Syscall, error) {
	c := &connectSyscall{}
	argsContainer := reflect.ValueOf(&c.args).Elem()
	bindOnlyArgsContainer := reflect.ValueOf(&c.bindOnlyArgs).Elem()
	retValContainer := reflect.ValueOf(c).Elem()
	return base.New(name, rawArgs, fieldBindings, argsContainer, bindOnlyArgsContainer, retValContainer, nil, c.run,
		nil)
}

func (c *connectSyscall) run(_ context.Context) error {
	if err := unix.Connect(c.args.FD, c.args.Address); err != nil {
		return err
	}

	c.Ret = 0
	return nil
}
