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

//go:build !arm64

package dup2

import (
	"context"
	"fmt"
	"reflect"

	"golang.org/x/sys/unix"

	"github.com/falcosecurity/event-generator/pkg/test/step"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/base"
)

type dup2Syscall struct {
	*base.Syscall
	// args represents arguments that can be provided by value or by binding.
	args struct {
		OldFD int `field_type:"fd"`
		NewFD int `field_type:"fd"`
	}
	// bindOnlyArgs represents arguments that can only be provided by binding.
	bindOnlyArgs struct{}
	savedFD      int
	Ret          int `field_type:"fd"`
}

// New creates a new dup2 system call test step.
func New(name string, rawArgs map[string]any, fieldBindings []*step.FieldBinding) (syscall.Syscall, error) {
	d := &dup2Syscall{savedFD: -1}
	argsContainer := reflect.ValueOf(&d.args).Elem()
	bindOnlyArgsContainer := reflect.ValueOf(&d.bindOnlyArgs).Elem()
	retValContainer := reflect.ValueOf(d).Elem()
	var err error
	d.Syscall, err = base.New(name, rawArgs, fieldBindings, argsContainer, bindOnlyArgsContainer, retValContainer, nil)
	if err != nil {
		return nil, err
	}
	return d, nil
}

func (d *dup2Syscall) Run(_ context.Context) error {
	if err := d.CheckUnboundArgField(); err != nil {
		return err
	}

	if d.savedFD != -1 {
		return fmt.Errorf("cannot re-run the step without performing cleanup first")
	}

	if d.args.NewFD < 3 {
		savedFD, err := unix.Dup(d.args.NewFD)
		if err != nil {
			return err
		}
		d.savedFD = savedFD
	}

	if _, _, err := unix.Syscall(unix.SYS_DUP2, uintptr(d.args.OldFD), uintptr(d.args.NewFD), 0); err != 0 {
		_ = unix.Close(d.savedFD)
		d.savedFD = -1
		return err
	}

	d.Ret = d.args.NewFD
	return nil
}

func (d *dup2Syscall) Cleanup(_ context.Context) error {
	if d.savedFD == -1 {
		return nil
	}

	defer func() {
		_ = unix.Close(d.savedFD)
		d.savedFD = -1
	}()

	if err := unix.Dup2(d.savedFD, d.args.NewFD); err != nil {
		return err
	}

	return nil
}
