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

package symlinkat

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

type symlinkAtSyscall struct {
	*base.Syscall
	// args represents arguments that can be provided by value or by binding.
	args struct {
		Target   []byte `field_type:"file_path"`
		LinkPath []byte `field_type:"file_path"`
	}
	// bindOnlyArgs represents arguments that can only be provided by binding.
	bindOnlyArgs struct {
		NewDirFD int `field_type:"fd"`
	}
	savedLinkPath []byte
	// Return value is neither set nor bindable.
}

// New creates a new symlinkat system call test step.
func New(name string, rawArgs map[string]any, fieldBindings []*step.FieldBinding) (syscall.Syscall, error) {
	s := &symlinkAtSyscall{}
	s.bindOnlyArgs.NewDirFD = unix.AT_FDCWD
	argsContainer := reflect.ValueOf(&s.args).Elem()
	bindOnlyArgsContainer := reflect.ValueOf(&s.bindOnlyArgs).Elem()
	retValContainer := reflect.ValueOf(s).Elem()
	defaultedArgs := []string{"newdirfd"}
	var err error
	s.Syscall, err = base.New(name, rawArgs, fieldBindings, argsContainer, bindOnlyArgsContainer, retValContainer,
		defaultedArgs)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (s *symlinkAtSyscall) Run(_ context.Context) error {
	if err := s.CheckUnboundArgField(); err != nil {
		return err
	}

	if s.savedLinkPath != nil {
		return fmt.Errorf("cannot re-run the step without performing cleanup first")
	}

	//nolint:gosec // System call invocation requires access to the raw pointer.
	targetPtr := unsafe.Pointer(&s.args.Target[0])
	//nolint:gosec // System call invocation requires access to the raw pointer.
	linkPathPtr := unsafe.Pointer(&s.args.LinkPath[0])
	if _, _, err := unix.Syscall(unix.SYS_SYMLINKAT, uintptr(targetPtr), uintptr(s.bindOnlyArgs.NewDirFD),
		uintptr(linkPathPtr)); err != 0 {
		return err
	}

	s.savedLinkPath = s.args.LinkPath
	return nil
}

func (s *symlinkAtSyscall) Cleanup(_ context.Context) error {
	if s.savedLinkPath == nil {
		return nil
	}

	defer func() {
		s.savedLinkPath = nil
	}()

	dirFD := s.bindOnlyArgs.NewDirFD
	//nolint:gosec // System call invocation requires access to the raw pointer.
	savedLinkPathPtr := unsafe.Pointer(&s.savedLinkPath[0])
	flags := 0
	if _, _, err := unix.Syscall(unix.SYS_UNLINKAT, uintptr(dirFD), uintptr(savedLinkPathPtr),
		uintptr(flags)); err != 0 {
		return err
	}

	return nil
}
