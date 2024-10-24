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

package directory

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

// directoryFD implements a directory FD resource.
type directoryFD struct {
	logger logr.Logger
	// resourceName is the fd resource name.
	resourceName string
	// filePath is the path of the directory to open/create.
	dirPath string
	// created is valid after a successful call to Create and becomes invalid after a call to Destroy. It is true if
	// Create created a new file, whereas is false if the directory exists and Create simply opened it.
	created bool
	// fields defines the information exposed by directoryFD for binding.
	fields struct {
		// FD is the directory file descriptor. If the resource has not been Create'd yet, or it has been Destroy'ed, FD
		// is set to -1.
		FD int `field_type:"fd"`
	}
}

// Verify that directoryFD implements resource.Resource interface.
var _ resource.Resource = (*directoryFD)(nil)

// New creates a new directory FD resource.
func New(logger logr.Logger, resourceName, dirPath string) resource.Resource {
	d := &directoryFD{
		logger:       logger,
		resourceName: resourceName,
		dirPath:      dirPath,
	}
	d.fields.FD = -1
	return d
}

func (d *directoryFD) Name() string {
	return d.resourceName
}

// Create opens or creates a directory and exposes its file descriptor.
func (d *directoryFD) Create(_ context.Context) error {
	if d.fields.FD != -1 {
		return fmt.Errorf("directory %q is already open", d.dirPath)
	}

	created, fd, err := d.openOrCreateDir(d.dirPath)
	if err != nil {
		return fmt.Errorf("error opening/creating directory %q: %w", d.dirPath, err)
	}

	d.created = created
	d.fields.FD = fd
	return nil
}

// openOrCreateFile opens or creates a directory at the provided path. It returns a boolean value indicating if the
// directory has been created and the file descriptor of the opened directory.
func (d *directoryFD) openOrCreateDir(dirPath string) (created bool, dirFD int, err error) {
	// Check for path existence. If it doesn't exist, creates the directory. If it exists, verify it is a directory.
	stat, err := os.Stat(dirPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return false, 0, fmt.Errorf("error verifying path existence: %w", err)
		}

		if err := unix.Mkdir(dirPath, unix.S_IRUSR|unix.S_IWUSR); err != nil {
			return false, 0, fmt.Errorf("error creating directory: %w", err)
		}

		created = true
	} else if !stat.IsDir() {
		return false, 0, fmt.Errorf("path exists and is not a directory")
	}

	// Open the directory
	fd, err := unix.Open(dirPath, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		if created {
			if err := unix.Rmdir(dirPath); err != nil {
				d.logger.Error(err, "error deleting directory", "path", dirPath)
			}
		}
		return false, 0, fmt.Errorf("error opening directory: %w", err)
	}

	return created, fd, nil
}

// Destroy closes the exposed file descriptor and deletes the underlying directory (if it was created by Create).
func (d *directoryFD) Destroy(_ context.Context) error {
	dirPath := d.dirPath

	if d.fields.FD == -1 {
		return fmt.Errorf("directory %q is not open", dirPath)
	}

	defer func() {
		d.created = false
		d.fields.FD = -1
	}()

	logger := d.logger.WithValues("dirPath", d.dirPath)

	// Close the file descriptor.
	if err := unix.Close(d.fields.FD); err != nil {
		logger.Error(err, "Error closing directory")
	}

	if !d.created {
		return nil
	}

	// Delete the directory.
	if err := unix.Rmdir(dirPath); err != nil {
		logger.Error(err, "Error removing created directory")
	}

	return nil
}

func (d *directoryFD) Field(name string) (*field.Field, error) {
	fieldContainer := reflect.ValueOf(d.fields)
	return field.ByName(name, fieldContainer)
}
