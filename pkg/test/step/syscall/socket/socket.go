package socket

import (
	"context"
	"fmt"
	"github.com/falcosecurity/event-generator/pkg/test/step"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/base"
	"golang.org/x/sys/unix"
	"reflect"
)

type socketSyscall struct {
	// args represents arguments that can be provided by value or by binding.
	args struct {
		Domain   int `field_type:"socket_domain"`
		Type     int `field_type:"socket_type"`
		Protocol int `field_type:"socket_protocol"`
	}
	// bindOnlyArgs represents arguments that can only be provided by binding.
	bindOnlyArgs struct{}
	Ret          int `field_type:"fd"`
}

// New creates a new socket system call test step.
func New(name string, rawArgs map[string]string,
	fieldBindings []*step.FieldBinding) (syscall.Syscall, error) {
	s := &socketSyscall{}
	argsContainer := reflect.ValueOf(&s.args).Elem()
	bindOnlyArgsContainer := reflect.ValueOf(&s.bindOnlyArgs).Elem()
	retValContainer := reflect.ValueOf(s).Elem()
	reflect.ValueOf(*s)
	return base.New(name, rawArgs, fieldBindings, argsContainer, bindOnlyArgsContainer, retValContainer, nil, s.run,
		nil)
}

func (s *socketSyscall) run(_ context.Context) error {
	fd, err := unix.Socket(s.args.Domain, s.args.Type, s.args.Protocol)
	if err != nil {
		return err
	}

	fmt.Printf("running socket: returned fd: %v\n", fd)
	s.Ret = fd
	return nil
}
