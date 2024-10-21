package dup

import (
	"context"
	"github.com/falcosecurity/event-generator/pkg/test/step"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/base"
	"golang.org/x/sys/unix"
	"reflect"
)

type dupSyscall struct {
	// args represents arguments that can be provided by value or by binding.
	args struct {
		OldFD int `field_type:"fd"`
	}
	// bindOnlyArgs represents arguments that can only be provided by binding.
	bindOnlyArgs struct{}
	Ret          int `field_type:"fd"`
}

// New creates a new dup system call test step.
func New(name string, rawArgs map[string]string,
	fieldBindings []*step.FieldBinding) (syscall.Syscall, error) {
	d := &dupSyscall{}
	argsContainer := reflect.ValueOf(&d.args).Elem()
	bindOnlyArgsContainer := reflect.ValueOf(&d.bindOnlyArgs).Elem()
	retValContainer := reflect.ValueOf(d).Elem()
	return base.New(name, rawArgs, fieldBindings, argsContainer, bindOnlyArgsContainer, retValContainer, nil, d.run, nil)
}

func (d *dupSyscall) run(_ context.Context) error {
	fd, err := unix.Dup(d.args.OldFD)
	if err != nil {
		return err
	}

	d.Ret = fd
	return nil
}
