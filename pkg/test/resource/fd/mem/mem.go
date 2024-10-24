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

package mem

import (
	"context"
	"fmt"
	"reflect"

	"github.com/go-logr/logr"
	"golang.org/x/sys/unix"

	"github.com/falcosecurity/event-generator/pkg/test/field"
	"github.com/falcosecurity/event-generator/pkg/test/resource"
)

// memFD implements a mem FD resource.
type memFD struct {
	logger logr.Logger
	// resourceName is the fd resource name.
	resourceName string
	// fileName is the file name associated with the mem FD.
	fileName string
	// fields defines the information exposed by memFD for binding.
	fields struct {
		FD int `field_type:"fd"`
	}
}

// Verify that memFD implements resource.Resource interface.
var _ resource.Resource = (*memFD)(nil)

// New creates a new mem FD resource.
func New(logger logr.Logger, resourceName, fileName string) resource.Resource {
	m := &memFD{
		logger:       logger,
		resourceName: resourceName,
		fileName:     fileName,
	}
	m.fields.FD = -1
	return m
}

func (m *memFD) Name() string {
	return m.resourceName
}

// Create creates a mem file descriptor and exposes it.
func (m *memFD) Create(_ context.Context) error {
	if m.fields.FD != -1 {
		return fmt.Errorf("mem FD %q is already open", m.fileName)
	}

	fd, err := createMemFD(m.fileName)
	if err != nil {
		return fmt.Errorf("error creating mem FD %q: %w", m.fileName, err)
	}

	m.fields.FD = fd
	return nil
}

// createMemFD creates a new mem file descriptor with the provided name and returns it.
func createMemFD(name string) (int, error) {
	fd, err := unix.MemfdCreate(name, 0)
	if err != nil {
		return 0, err
	}

	return fd, nil
}

// Destroy closes the exposed file descriptor.
func (m *memFD) Destroy(_ context.Context) error {
	if m.fields.FD == -1 {
		return fmt.Errorf("mem FD %q is not open", m.fileName)
	}

	defer func() {
		m.fields.FD = -1
	}()

	if err := unix.Close(m.fields.FD); err != nil {
		m.logger.Error(err, "Error closing mem FD", "fileName", m.fileName)
	}

	return nil
}

func (m *memFD) Field(name string) (*field.Field, error) {
	fieldContainer := reflect.ValueOf(m.fields)
	return field.ByName(name, fieldContainer)
}
