package linkat

import (
	"context"
	"github.com/falcosecurity/event-generator/pkg/test/step"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/base"
	"golang.org/x/sys/unix"
	"reflect"
	"unsafe"
)

type linkAtSyscall struct {
	// args represents arguments that can be provided by value or by binding.
	args struct {
		OldPath []byte `field_type:"file_path"`
		NewPath []byte `field_type:"file_path"`
		Flags   int    `field_type:"linkat_flags"`
	}
	// bindOnlyArgs represents arguments that can only be provided by binding.
	bindOnlyArgs struct {
		OldDirFD int `field_type:"fd"`
		NewDirFD int `field_type:"fd"`
	}
	Ret int
}

// New creates a new linkat system call test step.
func New(name string, rawArgs map[string]string, fieldBindings []*step.FieldBinding) (syscall.Syscall, error) {
	l := &linkAtSyscall{}
	l.bindOnlyArgs.OldDirFD = unix.AT_FDCWD
	l.bindOnlyArgs.NewDirFD = unix.AT_FDCWD
	// l.args.Flags defaulted to 0
	argsContainer := reflect.ValueOf(&l.args).Elem()
	bindOnlyArgsContainer := reflect.ValueOf(&l.bindOnlyArgs).Elem()
	retValContainer := reflect.ValueOf(l).Elem()
	defaultedArgs := []string{"olddirfd", "newdirfd", "flags"}
	return base.New(name, rawArgs, fieldBindings, argsContainer, bindOnlyArgsContainer, retValContainer, defaultedArgs,
		l.run, nil)
}

func (l *linkAtSyscall) run(_ context.Context) error {
	oldPathPtr := unsafe.Pointer(&l.args.OldPath[0])
	newPathPtr := unsafe.Pointer(&l.args.NewPath[0])
	if _, _, err := unix.Syscall6(unix.SYS_OPENAT, uintptr(l.bindOnlyArgs.OldDirFD), uintptr(oldPathPtr),
		uintptr(l.bindOnlyArgs.NewDirFD), uintptr(newPathPtr), uintptr(l.args.Flags), 0); err != 0 {
		return err
	}

	return nil
}
