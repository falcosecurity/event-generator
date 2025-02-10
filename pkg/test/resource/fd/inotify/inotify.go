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

package inotify

import (
	"context"
	"fmt"
	"reflect"

	"github.com/go-logr/logr"
	"golang.org/x/sys/unix"

	"github.com/falcosecurity/event-generator/pkg/test/field"
	"github.com/falcosecurity/event-generator/pkg/test/resource"
)

// inotifyFD implements an inotify FD resource.
type inotifyFD struct {
	logger logr.Logger
	// resourceName is the fd resource name.
	resourceName string
	// fields defines the information exposed by inotifyFD for binding.
	fields struct {
		// FD is the inotify file descriptor. If the resource has not been Create'd yet, or it has been Destroy'ed, FD
		// is set to -1.
		FD int `field_type:"fd"`
	}
}

// Verify that inotifyFD implements resource.Resource interface.
var _ resource.Resource = (*inotifyFD)(nil)

// New creates a new inotify FD resource.
func New(logger logr.Logger, resourceName string) resource.Resource {
	i := &inotifyFD{
		logger:       logger,
		resourceName: resourceName,
	}
	i.fields.FD = -1
	return i
}

func (i *inotifyFD) Name() string {
	return i.resourceName
}

// Create creates an inotify file descriptor and exposes it.
func (i *inotifyFD) Create(_ context.Context) error {
	if i.fields.FD != -1 {
		return fmt.Errorf("inotify FD is already open")
	}

	fd, err := createInotifyFD()
	if err != nil {
		return fmt.Errorf("error creating inotify FD: %w", err)
	}

	i.fields.FD = fd
	return nil
}

// createInotifyFD creates a new inotify file descriptor and returns it.
func createInotifyFD() (int, error) {
	fd, err := unix.InotifyInit()
	if err != nil {
		return 0, err
	}

	return fd, nil
}

// Destroy closes the exposed file descriptor.
func (i *inotifyFD) Destroy(_ context.Context) error {
	if i.fields.FD == -1 {
		return fmt.Errorf("inotify FD is not open")
	}

	defer func() {
		i.fields.FD = -1
	}()

	if err := unix.Close(i.fields.FD); err != nil {
		i.logger.Error(err, "Error closing inotify FD")
	}

	return nil
}

func (i *inotifyFD) Field(name string) (*field.Field, error) {
	fieldContainer := reflect.ValueOf(i.fields)
	return field.ByName(name, fieldContainer)
}
