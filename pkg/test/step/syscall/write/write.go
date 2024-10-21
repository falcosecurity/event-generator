package write

import (
	"context"
	"github.com/falcosecurity/event-generator/pkg/test/step"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/base"
	"golang.org/x/sys/unix"
	"reflect"
)

type writeSyscall struct {
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

// New creates a new write system call test step.
func New(name string, rawArgs map[string]string,
	fieldBindings []*step.FieldBinding) (syscall.Syscall, error) {
	w := &writeSyscall{}
	// s.args.Len defaults to the buffer length at run time, if unbound.
	argsContainer := reflect.ValueOf(&w.args).Elem()
	bindOnlyArgsContainer := reflect.ValueOf(&w.bindOnlyArgs).Elem()
	retValContainer := reflect.ValueOf(w).Elem()
	defaultedArgs := []string{"len"}
	return base.New(name, rawArgs, fieldBindings, argsContainer, bindOnlyArgsContainer, retValContainer, defaultedArgs,
		w.run, nil)
}

func (w *writeSyscall) run(_ context.Context) error {
	length := w.args.Len
	if length == 0 {
		length = len(w.args.Buffer)
	}
	writtenBytes, err := unix.Write(w.args.FD, w.args.Buffer[:length])
	if err != nil {
		return err
	}

	w.Ret = writtenBytes
	return nil
}
