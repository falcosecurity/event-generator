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

package socket

import (
	"context"
	"reflect"

	"golang.org/x/sys/unix"

	"github.com/falcosecurity/event-generator/pkg/test/step"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/base"
)

type socketSyscall struct {
	*base.Syscall
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
func New(name string, rawArgs map[string]any, fieldBindings []*step.FieldBinding) (syscall.Syscall, error) {
	s := &socketSyscall{}
	argsContainer := reflect.ValueOf(&s.args).Elem()
	bindOnlyArgsContainer := reflect.ValueOf(&s.bindOnlyArgs).Elem()
	retValContainer := reflect.ValueOf(s).Elem()
	var err error
	s.Syscall, err = base.New(name, rawArgs, fieldBindings, argsContainer, bindOnlyArgsContainer, retValContainer)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (s *socketSyscall) Run(_ context.Context) error {
	if err := s.CheckUnboundArgField(); err != nil {
		return err
	}

	fd, err := unix.Socket(s.args.Domain, s.args.Type, s.args.Protocol)
	if err != nil {
		return err
	}

	s.Ret = fd
	return nil
}
