package dup3

import (
	"context"
	"fmt"
	"github.com/falcosecurity/event-generator/pkg/test/step"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/base"
	"golang.org/x/sys/unix"
	"reflect"
)

type dup3Syscall struct {
	// args represents arguments that can be provided by value or by binding.
	args struct {
		OldFD int `field_type:"fd"`
		NewFD int `field_type:"fd"`
		Flags int `field_type:"dup3_flags"`
	}
	// bindOnlyArgs represents arguments that can only be provided by binding.
	bindOnlyArgs struct{}
	savedFD      int
	Ret          int `field_type:"fd"`
}

// New creates a new dup3 system call test step.
func New(name string, rawArgs map[string]string,
	fieldBindings []*step.FieldBinding) (syscall.Syscall, error) {
	d := &dup3Syscall{}
	// d.args.Flags defaulted to 0
	argsContainer := reflect.ValueOf(&d.args).Elem()
	bindOnlyArgsContainer := reflect.ValueOf(&d.bindOnlyArgs).Elem()
	retValContainer := reflect.ValueOf(d).Elem()
	defaultedArgs := []string{"flags"}
	return base.New(name, rawArgs, fieldBindings, argsContainer, bindOnlyArgsContainer, retValContainer, defaultedArgs,
		d.run, nil)
}

func (d *dup3Syscall) run(_ context.Context) error {
	if d.savedFD != -1 {
		return fmt.Errorf("cannot run without performing cleanup first")
	}

	if d.args.NewFD < 3 {
		savedFD, err := unix.Dup(d.args.NewFD)
		if err != nil {
			return err
		}
		d.savedFD = savedFD
	}

	if err := unix.Dup3(d.args.OldFD, d.args.NewFD, d.args.Flags); err != nil {
		_ = unix.Close(d.savedFD)
		d.savedFD = -1
		return err
	}

	d.Ret = d.args.NewFD
	return nil
}

func (d *dup3Syscall) cleanup(_ context.Context) error {
	if d.savedFD == -1 {
		return nil
	}

	defer func() {
		_ = unix.Close(d.savedFD)
		d.savedFD = -1
	}()

	if err := unix.Dup2(d.savedFD, d.args.NewFD); err != nil {
		return err
	}

	return nil
}
