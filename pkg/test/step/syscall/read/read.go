package read

import (
	"context"
	"github.com/falcosecurity/event-generator/pkg/test/step"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/base"
	"golang.org/x/sys/unix"
	"reflect"
)

type readSyscall struct {
	// args represents arguments that can be provided by value or by binding.
	args struct {
		FD     int    `field_type:"fd"`
		Buffer []byte `field_type:"buffer"`
		Len    int    `field_type:"buffer_len"`
	}
	// bindOnlyArgs represents arguments that can only be provided by binding.
	bindOnlyArgs struct{}
	Ret          int `field_type:"buffer_len"`
}

// New creates a new read system call test step.
func New(name string, rawArgs map[string]string,
	fieldBindings []*step.FieldBinding) (syscall.Syscall, error) {
	r := &readSyscall{}
	argsContainer := reflect.ValueOf(&r.args).Elem()
	bindOnlyArgsContainer := reflect.ValueOf(&r.bindOnlyArgs).Elem()
	retValContainer := reflect.ValueOf(r).Elem()
	return base.New(name, rawArgs, fieldBindings, argsContainer, bindOnlyArgsContainer, retValContainer, nil, r.run,
		nil)
}

func (r *readSyscall) run(_ context.Context) error {
	length := r.args.Len
	buffer := r.args.Buffer
	if length != 0 && len(buffer) == 0 {
		buffer = make([]byte, length)
	} else if length == 0 && len(buffer) > 0 {
		length = len(buffer)
	}

	readBytes, err := unix.Read(r.args.FD, buffer[:length])
	if err != nil {
		return err
	}

	r.Ret = readBytes
	return nil
}
