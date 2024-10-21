package symlinkat

import (
	"context"
	"github.com/falcosecurity/event-generator/pkg/test/step"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/base"
	"golang.org/x/sys/unix"
	"reflect"
	"unsafe"
)

type symlinkAtSyscall struct {
	// args represents arguments that can be provided by value or by binding.
	args struct {
		Target   []byte `field_type:"file_path"`
		LinkPath []byte `field_type:"file_path"`
	}
	// bindOnlyArgs represents arguments that can only be provided by binding.
	bindOnlyArgs struct {
		NewDirFD int `field_type:"fd"`
	}
	Ret int
}

// New creates a new symlinkat system call test step.
func New(name string, rawArgs map[string]string,
	fieldBindings []*step.FieldBinding) (syscall.Syscall, error) {
	s := &symlinkAtSyscall{}
	s.bindOnlyArgs.NewDirFD = unix.AT_FDCWD
	argsContainer := reflect.ValueOf(&s.args).Elem()
	bindOnlyArgsContainer := reflect.ValueOf(&s.bindOnlyArgs).Elem()
	retValContainer := reflect.ValueOf(s).Elem()
	defaultedArgs := []string{"newdirfd"}
	return base.New(name, rawArgs, fieldBindings, argsContainer, bindOnlyArgsContainer, retValContainer, defaultedArgs,
		s.run, nil)
}

func (s *symlinkAtSyscall) run(_ context.Context) error {
	targetPtr := unsafe.Pointer(&s.args.Target[0])
	linkPathPtr := unsafe.Pointer(&s.args.LinkPath[0])
	if _, _, err := unix.Syscall(unix.SYS_SYMLINKAT, uintptr(targetPtr), uintptr(s.bindOnlyArgs.NewDirFD),
		uintptr(linkPathPtr)); err != 0 {
		return err
	}

	return nil
}
