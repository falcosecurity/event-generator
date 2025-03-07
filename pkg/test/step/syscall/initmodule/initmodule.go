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

package initmodule

import (
	"context"
	"reflect"

	"golang.org/x/sys/unix"

	"github.com/falcosecurity/event-generator/pkg/test/step"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/base"
)

type initModuleSyscall struct {
	*base.Syscall
	// args represents arguments that can be provided by value or by binding.
	args struct {
		ModuleImage []byte `field_type:"buffer"`
		ParamValues string `field_type:"module_params"`
	}
	// bindOnlyArgs represents arguments that can only be provided by binding.
	bindOnlyArgs struct{}
	// Return value is neither set nor bindable.
}

// New creates a new init_module system call test step.
func New(name string, rawArgs map[string]any, fieldBindings []*step.FieldBinding) (syscall.Syscall, error) {
	i := &initModuleSyscall{}
	// i.args.ParamValues defaulted to ""
	argsContainer := reflect.ValueOf(&i.args).Elem()
	bindOnlyArgsContainer := reflect.ValueOf(&i.bindOnlyArgs).Elem()
	retValContainer := reflect.ValueOf(i).Elem()
	defaultedArgs := []string{"paramvalues"}
	var err error
	i.Syscall, err = base.New(name, rawArgs, fieldBindings, argsContainer, bindOnlyArgsContainer, retValContainer,
		base.WithDefaultedArgs(defaultedArgs))
	if err != nil {
		return nil, err
	}
	return i, nil
}

func (i *initModuleSyscall) Run(_ context.Context) error {
	if err := i.CheckUnboundArgField(); err != nil {
		return err
	}

	return unix.InitModule(i.args.ModuleImage, i.args.ParamValues)
}
