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

package dup

import (
	"context"
	"reflect"

	"golang.org/x/sys/unix"

	"github.com/falcosecurity/event-generator/pkg/test/step"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/base"
)

type dupSyscall struct {
	// args represents arguments that can be provided by value or by binding.
	args struct {
		OldFD int `field_type:"fd"`
	}
	// bindOnlyArgs represents arguments that can only be provided by binding.
	bindOnlyArgs struct{}
	Ret          int `field_type:"fd"`
}

// New creates a new dup system call test step.
func New(name string, rawArgs map[string]any, fieldBindings []*step.FieldBinding) (syscall.Syscall, error) {
	d := &dupSyscall{}
	argsContainer := reflect.ValueOf(&d.args).Elem()
	bindOnlyArgsContainer := reflect.ValueOf(&d.bindOnlyArgs).Elem()
	retValContainer := reflect.ValueOf(d).Elem()
	return base.New(name, rawArgs, fieldBindings, argsContainer, bindOnlyArgsContainer, retValContainer, nil, d.run,
		nil)
}

func (d *dupSyscall) run(_ context.Context) error {
	fd, err := unix.Dup(d.args.OldFD)
	if err != nil {
		return err
	}

	d.Ret = fd
	return nil
}
