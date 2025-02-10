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

package read

import (
	"context"
	"reflect"

	"golang.org/x/sys/unix"

	"github.com/falcosecurity/event-generator/pkg/test/step"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/base"
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
func New(name string, rawArgs map[string]any, fieldBindings []*step.FieldBinding) (syscall.Syscall, error) {
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
