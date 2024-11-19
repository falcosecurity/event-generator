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

//go:build !arm64

package link

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

type linkSyscall struct {
	// args represents arguments that can be provided by value or by binding.
	args struct {
		OldPath []byte `field_type:"file_path"`
		NewPath []byte `field_type:"file_path"`
	}
	// bindOnlyArgs represents arguments that can only be provided by binding.
	bindOnlyArgs struct{}
	savedNewPath []byte
	// Return value is neither set nor bindable.
}

// New creates a new link system call test step.
func New(name string, rawArgs map[string]string, fieldBindings []*step.FieldBinding) (syscall.Syscall, error) {
	l := &linkSyscall{}
	argsContainer := reflect.ValueOf(&l.args).Elem()
	bindOnlyArgsContainer := reflect.ValueOf(&l.bindOnlyArgs).Elem()
	retValContainer := reflect.ValueOf(l).Elem()
	return base.New(name, rawArgs, fieldBindings, argsContainer, bindOnlyArgsContainer, retValContainer, nil, l.run,
		l.cleanup)
}

func (l *linkSyscall) run(_ context.Context) error {
	if l.savedNewPath != nil {
		return fmt.Errorf("cannot re-run the step without performing cleanup first")
	}

	//nolint:gosec // System call invocation requires access to the raw pointer.
	oldPathPtr := unsafe.Pointer(&l.args.OldPath[0])
	//nolint:gosec // System call invocation requires access to the raw pointer.
	newPathPtr := unsafe.Pointer(&l.args.NewPath[0])
	if _, _, err := unix.Syscall(unix.SYS_LINK, uintptr(oldPathPtr), uintptr(newPathPtr), 0); err != 0 {
		return err
	}

	l.savedNewPath = l.args.NewPath
	return nil
}

func (l *linkSyscall) cleanup(_ context.Context) error {
	if l.savedNewPath == nil {
		return nil
	}

	defer func() {
		l.savedNewPath = nil
	}()

	//nolint:gosec // System call invocation requires access to the raw pointer.
	savedNewPathPtr := unsafe.Pointer(&l.savedNewPath[0])
	if _, _, err := unix.Syscall(unix.SYS_UNLINK, uintptr(savedNewPathPtr), 0, 0); err != 0 {
		return err
	}

	return nil
}
