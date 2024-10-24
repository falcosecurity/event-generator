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

package pipe

import (
	"context"
	"fmt"
	"reflect"

	"github.com/go-logr/logr"
	"golang.org/x/sys/unix"

	"github.com/falcosecurity/event-generator/pkg/test/field"
	"github.com/falcosecurity/event-generator/pkg/test/resource"
)

// pipe implements a pipe FD resource.
type pipe struct {
	logger logr.Logger
	// resourceName is the fd resource name.
	resourceName string
	// fields defines the information exposed by pipe for binding.
	fields struct {
		// ReadFD is the file descriptor of the pipe read end. If the resource has not been Create'd yet, or it has been
		// Destroy'ed, ReadFD is set to -1.
		ReadFD int `field_type:"fd"`
		// WriteFD is the file descriptor of the pipe write end. If the resource has not been Create'd yet, or it has
		// been Destroy'ed, ReadFD is set to -1.
		WriteFD int `field_type:"fd"`
	}
}

// Verify that pipe implements resource.Resource interface.
var _ resource.Resource = (*pipe)(nil)

// New creates a new pipe FD resource.
func New(logger logr.Logger, resourceName string) resource.Resource {
	p := &pipe{
		logger:       logger,
		resourceName: resourceName,
	}
	p.fields.ReadFD = -1
	p.fields.WriteFD = -1
	return p
}

func (p *pipe) Name() string {
	return p.resourceName
}

// Create a new pipe and exposes its file descriptors.
func (p *pipe) Create(_ context.Context) error {
	if p.fields.ReadFD != -1 {
		return fmt.Errorf("pipe is already open")
	}

	readFD, writeFD, err := createPipe()
	if err != nil {
		return fmt.Errorf("error creating pipe: %w", err)
	}

	p.fields.ReadFD = readFD
	p.fields.WriteFD = writeFD
	return nil
}

// createPipe creates a new pipe and returns its two file descriptors.
func createPipe() (readFD, writeFD int, err error) {
	var fds [2]int
	if err := unix.Pipe(fds[:]); err != nil {
		return 0, 0, err
	}

	return fds[0], fds[1], nil
}

// Destroy closes the exposed pipe file descriptors.
func (p *pipe) Destroy(_ context.Context) error {
	if p.fields.ReadFD == -1 {
		return fmt.Errorf("pipe is not open")
	}

	defer func() {
		p.fields.ReadFD = -1
		p.fields.WriteFD = -1
	}()

	if err := unix.Close(p.fields.ReadFD); err != nil {
		p.logger.Error(err, "Error closing pipe read end")
	}

	if err := unix.Close(p.fields.WriteFD); err != nil {
		p.logger.Error(err, "Error closing pipe write end")
	}

	return nil
}

func (p *pipe) Field(name string) (*field.Field, error) {
	fieldContainer := reflect.ValueOf(p.fields)
	return field.ByName(name, fieldContainer)
}
