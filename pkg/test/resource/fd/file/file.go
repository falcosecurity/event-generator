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

package file

import (
	"context"
	"fmt"
	"os"
	"reflect"

	"github.com/go-logr/logr"
	"golang.org/x/sys/unix"

	"github.com/falcosecurity/event-generator/pkg/test/field"
	"github.com/falcosecurity/event-generator/pkg/test/resource"
)

// regularFD implements a regular file FD resource.
type regularFD struct {
	logger logr.Logger
	// resourceName is the fd resource name.
	resourceName string
	// filePath is the path of the file to open/create.
	filePath string
	// created is valid after a successful call to Create and becomes invalid after a call to Destroy. It is true if
	// Create created a new file, whereas is false if the file exists and Create simply opened it.
	created bool
	// fields defines the information exposed by regularFD for binding.
	fields struct {
		// FD is the regular file descriptor. If the resource has not been Create'd yet, or it has been Destroy'ed, FD
		// is set to -1.
		FD int `field_type:"fd"`
	}
}

// Verify that regularFD implements resource.Resource interface.
var _ resource.Resource = (*regularFD)(nil)

// New creates a new regular file FD resource.
func New(logger logr.Logger, resourceName, filePath string) resource.Resource {
	cs := &regularFD{
		logger:       logger,
		resourceName: resourceName,
		filePath:     filePath,
	}
	cs.fields.FD = -1
	return cs
}

func (r *regularFD) Name() string {
	return r.resourceName
}

// Create opens or creates a regular file and exposes its file descriptor.
func (r *regularFD) Create(_ context.Context) error {
	if r.fields.FD != -1 {
		return fmt.Errorf("file %q is already open", r.filePath)
	}

	created, fd, err := openOrCreateFile(r.filePath)
	if err != nil {
		return fmt.Errorf("error opening/creating file %q: %w", r.filePath, err)
	}

	r.created = created
	r.fields.FD = fd
	return nil
}

// openOrCreateFile opens or creates a regular file at the provided path.
func openOrCreateFile(path string) (created bool, fileFD int, err error) {
	mustCreate := false

	// Check for file existence.
	if _, err := os.Stat(path); err != nil {
		if !os.IsNotExist(err) {
			return false, 0, fmt.Errorf("error verifying file existence: %w", err)
		}

		mustCreate = true
	}

	// Open/Create the file.
	flags := unix.O_RDWR
	if mustCreate {
		flags |= unix.O_CREAT
	}
	fd, err := unix.Open(path, flags, 0)
	if err != nil {
		return false, 0, fmt.Errorf("error opening the file: %w", err)
	}

	return mustCreate, fd, nil
}

// Destroy closes the exposed file descriptor and deletes the underlying file (if it was created by Create).
func (r *regularFD) Destroy(_ context.Context) error {
	filePath := r.filePath

	if r.fields.FD == -1 {
		return fmt.Errorf("file %q is not open", filePath)
	}

	defer func() {
		r.fields.FD = -1
		r.created = false
	}()

	logger := r.logger.WithValues("filePath", filePath)

	// Close the file descriptor.
	if err := unix.Close(r.fields.FD); err != nil {
		logger.Error(err, "Error closing file")
	}

	if !r.created {
		return nil
	}

	// Delete the file.
	if err := unix.Unlink(filePath); err != nil {
		logger.Error(err, "Error removing created file")
	}

	return nil
}

func (r *regularFD) Field(name string) (*field.Field, error) {
	fieldContainer := reflect.ValueOf(r.fields)
	return field.ByName(name, fieldContainer)
}
