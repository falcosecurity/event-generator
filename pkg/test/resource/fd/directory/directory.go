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

package directory

import (
	"context"
	"fmt"
	"os"
	"reflect"

	"github.com/go-logr/logr"
	"golang.org/x/sys/unix"

	"github.com/falcosecurity/event-generator/pkg/osutil"
	"github.com/falcosecurity/event-generator/pkg/test/field"
	"github.com/falcosecurity/event-generator/pkg/test/resource"
)

// directoryFD implements a directory FD resource.
type directoryFD struct {
	logger logr.Logger
	// resourceName is the fd resource name.
	resourceName string
	// dirPath is the path of the directory to open/create.
	dirPath string
	// firstCreatedDirPath is valid after a successful call to Create and becomes invalid after a call to Destroy. It
	// contains the path of the first created directory in the directory hierarchy leading to dirPath. If no new
	// directories have been created, it is empty.
	firstCreatedDirPath string
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

	dirPath := d.dirPath

	// Ensure the directory exists.
	firstCreatedDirPath, err := osutil.MkdirAll(dirPath)
	if err != nil {
		return fmt.Errorf("error creating directory hierarchy %q: %w", dirPath, err)
	}

	// Open the directory.
	fd, err := unix.Open(dirPath, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		if firstCreatedDirPath != "" {
			if err := os.RemoveAll(firstCreatedDirPath); err != nil {
				d.logger.Error(err, "Error removing created directory hierarchy", "dirHierarchyRootPath",
					firstCreatedDirPath)
			}
		}
		return fmt.Errorf("error opening directory: %w", err)
	}

	d.firstCreatedDirPath = firstCreatedDirPath
	d.fields.FD = fd
	return nil
}

// Destroy closes the exposed file descriptor and deletes the underlying directory (if it was created by Create).
func (d *directoryFD) Destroy(_ context.Context) error {
	dirPath := d.dirPath

	if d.fields.FD == -1 {
		return fmt.Errorf("directory %q is not open", dirPath)
	}

	defer func() {
		d.firstCreatedDirPath = ""
		d.fields.FD = -1
	}()

	logger := d.logger.WithValues("dirPath", d.dirPath)

	// Close the file descriptor.
	if err := unix.Close(d.fields.FD); err != nil {
		logger.Error(err, "Error closing directory")
	}

	firstCreatedDirPath := d.firstCreatedDirPath
	if firstCreatedDirPath == "" {
		return nil
	}

	// Delete the directory as well as any created parent directory.
	if err := os.RemoveAll(firstCreatedDirPath); err != nil {
		logger.Error(err, "Error removing created directory hierarchy", "dirHierarchyRootPath", firstCreatedDirPath)
	}

	return nil
}

func (d *directoryFD) Field(name string) (*field.Field, error) {
	fieldContainer := reflect.ValueOf(d.fields)
	return field.ByName(name, fieldContainer)
}
