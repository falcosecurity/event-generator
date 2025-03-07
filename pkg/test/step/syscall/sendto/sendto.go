// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 The Falco Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sendto

import (
	"context"
	"reflect"

	"golang.org/x/sys/unix"

	"github.com/falcosecurity/event-generator/pkg/test/step"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/base"
)

type sendToSyscall struct {
	*base.Syscall
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
}

// New creates a new sendto system call test step.
func New(name string, rawArgs map[string]any, fieldBindings []*step.FieldBinding) (syscall.Syscall, error) {
	s := &sendToSyscall{}
	// s.args.Len defaults to the buffer length at run time, if unbound.
	argsContainer := reflect.ValueOf(&s.args).Elem()
	bindOnlyArgsContainer := reflect.ValueOf(&s.bindOnlyArgs).Elem()
	retValContainer := reflect.ValueOf(s).Elem()
	defaultedArgs := []string{"len"}
	var err error
	s.Syscall, err = base.New(name, rawArgs, fieldBindings, argsContainer, bindOnlyArgsContainer, retValContainer,
		base.WithDefaultedArgs(defaultedArgs))
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (s *sendToSyscall) Run(_ context.Context) error {
	if err := s.CheckUnboundArgField(); err != nil {
		return err
	}

	length := s.args.Len
	if length == 0 {
		length = len(s.args.Buf)
	}
	return unix.Sendto(s.bindOnlyArgs.FD, s.args.Buf[:length], s.args.Flags, s.args.DestAddr)
}
