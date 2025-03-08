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

package write

import (
	"context"
	"reflect"

	"golang.org/x/sys/unix"

	"github.com/falcosecurity/event-generator/pkg/test/step"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/base"
)

type writeSyscall struct {
	*base.Syscall
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
func New(name string, rawArgs map[string]any, fieldBindings []*step.FieldBinding) (syscall.Syscall, error) {
	w := &writeSyscall{}
	// w.args.Len defaults to the buffer length at run time, if unbound.
	argsContainer := reflect.ValueOf(&w.args).Elem()
	bindOnlyArgsContainer := reflect.ValueOf(&w.bindOnlyArgs).Elem()
	retValContainer := reflect.ValueOf(w).Elem()
	defaultedArgs := []string{"len"}
	var err error
	w.Syscall, err = base.New(name, rawArgs, fieldBindings, argsContainer, bindOnlyArgsContainer, retValContainer,
		defaultedArgs)
	if err != nil {
		return nil, err
	}
	return w, nil
}

func (w *writeSyscall) Run(_ context.Context) error {
	if err := w.CheckUnboundArgField(); err != nil {
		return err
	}

	length := w.args.Len
	if length == 0 {
		length = len(w.args.Buffer)
	}
	writtenBytes, err := unix.Write(w.args.FD, w.args.Buffer[:length])
	if err != nil {
		return err
	}

	w.args.Len = length
	w.Ret = writtenBytes
	return nil
}
