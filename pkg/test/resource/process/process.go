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

package process

import (
	"context"
	"fmt"
	"reflect"

	"github.com/go-logr/logr"

	"github.com/falcosecurity/event-generator/pkg/process"
	"github.com/falcosecurity/event-generator/pkg/test/field"
	"github.com/falcosecurity/event-generator/pkg/test/resource"
)

// procRes implements a process resource.
type procRes struct {
	logger logr.Logger
	// resourceName is the process resource name.
	resourceName string

	proc process.Process
	// fields defines the information exposed by process for binding.
	fields struct {
		// PID is process identifier. If the resource has not been Create'd yet, or it has been Destroy'ed, PID is set
		// to -1.
		PID int `field_type:"pid"`
	}
}

// TODO: replace "cat" with "sleep infinity" when the process package will provide support for multiple arguments.
var processCommand = "cat"

// New creates a new process resource.
func New(logger logr.Logger, resourceName string, processBuilder process.Builder, simExePath, name, arg0, args string,
	env []string) resource.Resource {
	processBuilder.SetSimExePath(simExePath)
	processBuilder.SetName(name)
	processBuilder.SetArg0(arg0)
	processBuilder.SetArgs(args)
	processBuilder.SetEnv(env)
	proc := processBuilder.Build(context.Background(), logger, processCommand)

	p := &procRes{
		logger:       logger,
		resourceName: resourceName,
		proc:         proc,
	}
	p.fields.PID = -1
	return p
}

// Verify that process implements resource.Resource interface.
var _ resource.Resource = (*procRes)(nil)

func (p *procRes) Name() string {
	return p.resourceName
}

var (
	errProcessAlreadyStarted = fmt.Errorf("process already started")
	errProcessAlreadyExited  = fmt.Errorf("process already exited")
)

// Create creates a process and exposes its bindable fields.
func (p *procRes) Create(_ context.Context) error {
	if p.fields.PID != -1 {
		return errProcessAlreadyStarted
	}

	if err := p.proc.Start(); err != nil {
		return fmt.Errorf("error starting process: %w", err)
	}

	p.fields.PID = p.proc.PID()
	return nil
}

// Destroy closes the exposed file descriptor.
func (p *procRes) Destroy(_ context.Context) error {
	if p.fields.PID == -1 {
		return errProcessAlreadyExited
	}

	defer func() {
		p.proc = nil
		p.fields.PID = -1
	}()

	if err := p.proc.Kill(); err != nil {
		return fmt.Errorf("error killing process: %w", err)
	}

	return nil
}

func (p *procRes) Field(name string) (*field.Field, error) {
	fieldContainer := reflect.ValueOf(p.fields)
	return field.ByName(name, fieldContainer)
}
