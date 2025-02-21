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

package openat2

import (
	"context"
	"reflect"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/falcosecurity/event-generator/pkg/test/step"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/base"
)

type openAt2Syscall struct {
	*base.Syscall
	// args represents arguments that can be provided by value or by binding.
	args struct {
		Pathname []byte `field_type:"file_path"`
		How      struct {
			Flags   uint64 `field_type:"open_how_flags"`
			Mode    uint64 `field_type:"open_how_mode"`
			Resolve uint64 `field_type:"open_how_resolve"`
		} `field_type:"open_how"`
	}
	// bindOnlyArgs represents arguments that can only be provided by binding.
	bindOnlyArgs struct {
		DirFD int `field_type:"fd"`
	}
	Ret int `field_type:"fd"`
}

// New creates a new openat2 system call test step.
func New(name string, rawArgs map[string]any, fieldBindings []*step.FieldBinding) (syscall.Syscall, error) {
	o := &openAt2Syscall{}
	o.bindOnlyArgs.DirFD = unix.AT_FDCWD
	// o.args.How field defaulted to empty struct.
	argsContainer := reflect.ValueOf(&o.args).Elem()
	bindOnlyArgsContainer := reflect.ValueOf(&o.bindOnlyArgs).Elem()
	retValContainer := reflect.ValueOf(o).Elem()
	defaultedArgs := []string{"dirfd", "how", "how.flags", "how.mode", "how.resolve"}
	var err error
	o.Syscall, err = base.New(name, rawArgs, fieldBindings, argsContainer, bindOnlyArgsContainer, retValContainer,
		defaultedArgs)
	if err != nil {
		return nil, err
	}
	return o, nil
}

func (o *openAt2Syscall) Run(_ context.Context) error {
	if err := o.CheckUnboundArgField(); err != nil {
		return err
	}

	//nolint:gosec // System call invocation requires access to the raw pointer.
	pathnamePtr := unsafe.Pointer(&o.args.Pathname[0])
	//nolint:gosec // System call invocation requires access to the raw pointer.
	openHowPtr := unsafe.Pointer(&o.args.How)
	fd, _, err := unix.Syscall6(unix.SYS_OPENAT2, uintptr(o.bindOnlyArgs.DirFD), uintptr(pathnamePtr),
		uintptr(openHowPtr), uintptr(unix.SizeofOpenHow), 0, 0)
	if err != 0 {
		return err
	}

	o.Ret = int(fd)
	return nil
}
