// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 The Falco Authors
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

package finitmodule

import (
	"context"
	"reflect"

	"golang.org/x/sys/unix"

	"github.com/falcosecurity/event-generator/pkg/test/step"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/base"
)

type finitModuleSyscall struct {
	// args represents arguments that can be provided by value or by binding.
	args struct {
		ParamValues string `field_type:"module_params"`
		Flags       int    `field_type:"finit_module_flags"`
	}
	// bindOnlyArgs represents arguments that can only be provided by binding.
	bindOnlyArgs struct {
		FD int `field_type:"fd"`
	}
	// Return value is neither set nor bindable.
}

// New creates a new finit_module system call test step.
func New(name string, rawArgs map[string]any, fieldBindings []*step.FieldBinding) (syscall.Syscall, error) {
	f := &finitModuleSyscall{}
	// f.args.ParamValues defaulted to ""
	// f.args.Flags defaulted to 0
	argsContainer := reflect.ValueOf(&f.args).Elem()
	bindOnlyArgsContainer := reflect.ValueOf(&f.bindOnlyArgs).Elem()
	retValContainer := reflect.ValueOf(f).Elem()
	defaultedArgs := []string{"paramvalues", "flags"}
	return base.New(name, rawArgs, fieldBindings, argsContainer, bindOnlyArgsContainer, retValContainer, defaultedArgs,
		f.run, nil)
}

func (f *finitModuleSyscall) run(_ context.Context) error {
	return unix.FinitModule(f.bindOnlyArgs.FD, f.args.ParamValues, f.args.Flags)
}
