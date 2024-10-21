package open

import (
	"context"
	"github.com/falcosecurity/event-generator/pkg/test/step"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/base"
	"golang.org/x/sys/unix"
	"reflect"
	"unsafe"
)

type openSyscall struct {
	// args represents arguments that can be provided by value or by binding.
	args struct {
		Pathname []byte `field_type:"file_path"`
		Flags    int    `field_type:"open_flags"`
		Mode     uint32 `field_type:"open_mode"`
	}
	// bindOnlyArgs represents arguments that can only be provided by binding.
	bindOnlyArgs struct{}
	Ret          int `field_type:"fd"`
}

// New creates a new open system call test step.
func New(name string, rawArgs map[string]string,
	fieldBindings []*step.FieldBinding) (syscall.Syscall, error) {
	o := &openSyscall{}
	// mode defaulted to 0
	argsContainer := reflect.ValueOf(&o.args).Elem()
	bindOnlyArgsContainer := reflect.ValueOf(&o.bindOnlyArgs).Elem()
	retValContainer := reflect.ValueOf(o).Elem()
	defaultedArgs := []string{"mode"}
	return base.New(name, rawArgs, fieldBindings, argsContainer, bindOnlyArgsContainer, retValContainer, defaultedArgs,
		o.run, nil)
}

func (o *openSyscall) run(_ context.Context) error {
	pathnamePtr := unsafe.Pointer(&o.args.Pathname[0])
	fd, _, err := unix.Syscall(unix.SYS_OPEN, uintptr(pathnamePtr), uintptr(o.args.Flags), uintptr(o.args.Mode))
	if err != 0 {
		return err
	}

	o.Ret = int(fd)
	return nil
}
