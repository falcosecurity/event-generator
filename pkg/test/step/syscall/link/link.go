package link

import (
	"context"
	"github.com/falcosecurity/event-generator/pkg/test/step"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/base"
	"golang.org/x/sys/unix"
	"reflect"
	"unsafe"
)

type linkSyscall struct {
	// args represents arguments that can be provided by value or by binding.
	args struct {
		OldPath []byte `field_type:"file_path"`
		NewPath []byte `field_type:"file_path"`
	}
	// bindOnlyArgs represents arguments that can only be provided by binding.
	bindOnlyArgs struct{}
	Ret          int
}

// New creates a new link system call test step.
func New(name string, rawArgs map[string]string,
	fieldBindings []*step.FieldBinding) (syscall.Syscall, error) {
	l := &linkSyscall{}
	argsContainer := reflect.ValueOf(&l.args).Elem()
	bindOnlyArgsContainer := reflect.ValueOf(&l.bindOnlyArgs).Elem()
	retValContainer := reflect.ValueOf(l).Elem()
	return base.New(name, rawArgs, fieldBindings, argsContainer, bindOnlyArgsContainer, retValContainer, nil, l.run, nil)
}

func (l *linkSyscall) run(_ context.Context) error {
	oldPathPtr := unsafe.Pointer(&l.args.OldPath[0])
	newPathPtr := unsafe.Pointer(&l.args.NewPath[0])
	if _, _, err := unix.Syscall(unix.SYS_LINK, uintptr(oldPathPtr), uintptr(newPathPtr), 0); err != 0 {
		return err
	}

	return nil
}
