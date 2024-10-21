package sendto

import (
	"context"
	"github.com/falcosecurity/event-generator/pkg/test/step"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/base"
	"golang.org/x/sys/unix"
	"reflect"
)

type sendToSyscall struct {
	// args represents arguments that can be provided by value or by binding.
	args struct {
		Buf      []byte        `field_type:"buffer"`
		Len      int           `field_type:"buffer_len"`
		Flags    int           `field_type:"send_flags"`
		DestAddr unix.Sockaddr `field_type:"socket_address"`
	}
	// bindOnlyArgs represents arguments that can only be provided by binding.
	bindOnlyArgs struct {
		FD int `field_type:"fd"`
	}
	// FIXME:
	//  sendto system call returns the number of characters sent but both unix.Sendto and syscall.Sendto do not return
	//  it and do not allow to rewrite it by using direct calls to unix.Syscall or syscall.Syscall. For this reason, the
	//  returned value is currently neither set nor bindable.
	Ret int
}

// New creates a new sendto system call test step.
func New(name string, rawArgs map[string]string,
	fieldBindings []*step.FieldBinding) (syscall.Syscall, error) {
	s := &sendToSyscall{}
	// s.args.Len defaults to the buffer length at run time, if unbound.
	argsContainer := reflect.ValueOf(&s.args).Elem()
	bindOnlyArgsContainer := reflect.ValueOf(&s.bindOnlyArgs).Elem()
	retValContainer := reflect.ValueOf(s).Elem()
	defaultedArgs := []string{"len"}
	return base.New(name, rawArgs, fieldBindings, argsContainer, bindOnlyArgsContainer, retValContainer, defaultedArgs,
		s.run, nil)
}

func (s *sendToSyscall) run(_ context.Context) error {
	length := s.args.Len
	if length == 0 {
		length = len(s.args.Buf)
	}
	if err := unix.Sendto(s.bindOnlyArgs.FD, s.args.Buf[:length], s.args.Flags, s.args.DestAddr); err != nil {
		return err
	}

	return nil
}
