package symlink

import (
	"context"
	"github.com/falcosecurity/event-generator/pkg/test/step"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/base"
	"golang.org/x/sys/unix"
	"reflect"
	"unsafe"
)

type symlinkSyscall struct {
	// args represents arguments that can be provided by value or by binding.
	args struct {
		Target   []byte `field_type:"file_path"`
		LinkPath []byte `field_type:"file_path"`
	}
	// bindOnlyArgs represents arguments that can only be provided by binding.
	bindOnlyArgs struct{}
	Ret          int
}

// New creates a new symlink system call test step.
func New(name string, rawArgs map[string]string,
	fieldBindings []*step.FieldBinding) (syscall.Syscall, error) {
	s := &symlinkSyscall{}
	argsContainer := reflect.ValueOf(&s.args).Elem()
	bindOnlyArgsContainer := reflect.ValueOf(&s.bindOnlyArgs).Elem()
	retValContainer := reflect.ValueOf(s).Elem()
	return base.New(name, rawArgs, fieldBindings, argsContainer, bindOnlyArgsContainer, retValContainer, nil, s.run, nil)
}

func (s *symlinkSyscall) run(_ context.Context) error {
	targetPtr := unsafe.Pointer(&s.args.Target[0])
	linkPathPtr := unsafe.Pointer(&s.args.LinkPath[0])
	if _, _, err := unix.Syscall(unix.SYS_SYMLINK, uintptr(targetPtr), uintptr(linkPathPtr), 0); err != 0 {
		return err
	}

	return nil
}
