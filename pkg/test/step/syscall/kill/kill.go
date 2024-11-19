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

package kill

import (
	"context"
	"reflect"

	"golang.org/x/sys/unix"

	"github.com/falcosecurity/event-generator/pkg/test/step"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/base"
)

type killSyscall struct {
	// args represents arguments that can be provided by value or by binding.
	args struct {
		Sig unix.Signal `field_type:"signal"`
	}
	// bindOnlyArgs represents arguments that can only be provided by binding.
	bindOnlyArgs struct {
		PID int `field_type:"pid"`
	}
	// Return value is neither set nor bindable.
}

// New creates a new kill system call test step.
func New(name string, rawArgs map[string]string,
	fieldBindings []*step.FieldBinding) (syscall.Syscall, error) {
	k := &killSyscall{}
	argsContainer := reflect.ValueOf(&k.args).Elem()
	bindOnlyArgsContainer := reflect.ValueOf(&k.bindOnlyArgs).Elem()
	retValContainer := reflect.ValueOf(k).Elem()
	return base.New(name, rawArgs, fieldBindings, argsContainer, bindOnlyArgsContainer, retValContainer, nil, k.run,
		nil)
}

func (k *killSyscall) run(_ context.Context) error {
	return unix.Kill(k.bindOnlyArgs.PID, k.args.Sig)
}
