package openat2

import (
	"context"
	"github.com/falcosecurity/event-generator/pkg/test/step"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/base"
	"golang.org/x/sys/unix"
	"reflect"
	"unsafe"
)

type openAt2Syscall struct {
	// args represents arguments that can be provided by value or by binding.
	args struct {
		Pathname []byte       `field_type:"file_path"`
		How      unix.OpenHow `field_type:"open_how"`
	}
	// bindOnlyArgs represents arguments that can only be provided by binding.
	bindOnlyArgs struct {
		DirFD int `field_type:"fd"`
	}
	Ret int `field_type:"fd"`
}

// New creates a new openat2 system call test step.
func New(name string, rawArgs map[string]string,
	fieldBindings []*step.FieldBinding) (syscall.Syscall, error) {
	o := &openAt2Syscall{}
	o.bindOnlyArgs.DirFD = unix.AT_FDCWD
	// o.args.How fields defaulted to 0
	argsContainer := reflect.ValueOf(&o.args).Elem()
	bindOnlyArgsContainer := reflect.ValueOf(&o.bindOnlyArgs).Elem()
	retValContainer := reflect.ValueOf(o).Elem()
	defaultedArgs := []string{"dirfd", "mode"}
	return base.New(name, rawArgs, fieldBindings, argsContainer, bindOnlyArgsContainer, retValContainer, defaultedArgs,
		o.run, nil)
}

func (o *openAt2Syscall) run(_ context.Context) error {
	pathnamePtr := unsafe.Pointer(&o.args.Pathname[0])
	openHowPtr := unsafe.Pointer(&o.args.How)
	fd, _, err := unix.Syscall6(unix.SYS_OPENAT2, uintptr(o.bindOnlyArgs.DirFD), uintptr(pathnamePtr),
		uintptr(openHowPtr), uintptr(unix.SizeofOpenHow), 0, 0)
	if err != 0 {
		return err
	}

	o.Ret = int(fd)
	return nil
}
