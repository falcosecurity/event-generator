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

package linkat

import (
	"context"
	"fmt"
	"reflect"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/falcosecurity/event-generator/pkg/test/step"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/base"
)

type linkAtSyscall struct {
	// args represents arguments that can be provided by value or by binding.
	args struct {
		OldPath []byte `field_type:"file_path"`
		NewPath []byte `field_type:"file_path"`
		Flags   int    `field_type:"linkat_flags"`
	}
	// bindOnlyArgs represents arguments that can only be provided by binding.
	bindOnlyArgs struct {
		OldDirFD int `field_type:"fd"`
		NewDirFD int `field_type:"fd"`
	}
	savedNewPath []byte
	// Return value is neither set nor bindable.
}

// New creates a new linkat system call test step.
func New(name string, rawArgs map[string]any, fieldBindings []*step.FieldBinding) (syscall.Syscall, error) {
	l := &linkAtSyscall{}
	l.bindOnlyArgs.OldDirFD = unix.AT_FDCWD
	l.bindOnlyArgs.NewDirFD = unix.AT_FDCWD
	// l.args.Flags defaulted to 0
	argsContainer := reflect.ValueOf(&l.args).Elem()
	bindOnlyArgsContainer := reflect.ValueOf(&l.bindOnlyArgs).Elem()
	retValContainer := reflect.ValueOf(l).Elem()
	defaultedArgs := []string{"olddirfd", "newdirfd", "flags"}
	return base.New(name, rawArgs, fieldBindings, argsContainer, bindOnlyArgsContainer, retValContainer, defaultedArgs,
		l.run, l.cleanup)
}

func (l *linkAtSyscall) run(_ context.Context) error {
	if l.savedNewPath != nil {
		return fmt.Errorf("cannot re-run the step without performing cleanup first")
	}

	//nolint:gosec // System call invocation requires access to the raw pointer.
	oldPathPtr := unsafe.Pointer(&l.args.OldPath[0])
	//nolint:gosec // System call invocation requires access to the raw pointer.
	newPathPtr := unsafe.Pointer(&l.args.NewPath[0])
	if _, _, err := unix.Syscall6(unix.SYS_LINKAT, uintptr(l.bindOnlyArgs.OldDirFD), uintptr(oldPathPtr),
		uintptr(l.bindOnlyArgs.NewDirFD), uintptr(newPathPtr), uintptr(l.args.Flags), 0); err != 0 {
		return err
	}

	l.savedNewPath = l.args.NewPath
	return nil
}

func (l *linkAtSyscall) cleanup(_ context.Context) error {
	if l.savedNewPath == nil {
		return nil
	}

	defer func() {
		l.savedNewPath = nil
	}()

	newDirFD := l.bindOnlyArgs.NewDirFD
	//nolint:gosec // System call invocation requires access to the raw pointer.
	savedNewPathPtr := unsafe.Pointer(&l.savedNewPath[0])
	flags := 0
	if _, _, err := unix.Syscall(unix.SYS_UNLINKAT, uintptr(newDirFD), uintptr(savedNewPathPtr),
		uintptr(flags)); err != 0 {
		return err
	}

	return nil
}
