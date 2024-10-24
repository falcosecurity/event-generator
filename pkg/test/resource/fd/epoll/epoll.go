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

package epoll

import (
	"context"
	"fmt"
	"reflect"

	"github.com/go-logr/logr"
	"golang.org/x/sys/unix"

	"github.com/falcosecurity/event-generator/pkg/test/field"
	"github.com/falcosecurity/event-generator/pkg/test/resource"
)

// epollFD implements an epoll FD resource.
type epollFD struct {
	logger logr.Logger
	// resourceName is the fd resource name.
	resourceName string
	// fields defines the information exposed by epollFD for binding.
	fields struct {
		// FD is the epoll file descriptor. If the resource has not been Create'd yet, or it has been Destroy'ed, FD is
		// set to -1.
		FD int `field_type:"fd"`
	}
}

// Verify that epollFD implements resource.Resource interface.
var _ resource.Resource = (*epollFD)(nil)

// New creates a new epoll FD resource.
func New(logger logr.Logger, resourceName string) resource.Resource {
	e := &epollFD{
		logger:       logger,
		resourceName: resourceName,
	}
	e.fields.FD = -1
	return e
}

func (e *epollFD) Name() string {
	return e.resourceName
}

// Create creates an epoll file descriptor and exposes it.
func (e *epollFD) Create(_ context.Context) error {
	if e.fields.FD != -1 {
		return fmt.Errorf("epoll FD is already open")
	}

	fd, err := createEpollFD()
	if err != nil {
		return fmt.Errorf("error creating epoll FD: %w", err)
	}

	e.fields.FD = fd
	return nil
}

// createEpollFD creates a new epoll file descriptor and returns it.
func createEpollFD() (int, error) {
	fd, err := unix.EpollCreate1(0)
	if err != nil {
		return 0, err
	}

	return fd, nil
}

// Destroy closes the exposed file descriptor.
func (e *epollFD) Destroy(_ context.Context) error {
	if e.fields.FD == -1 {
		return fmt.Errorf("epoll FD is not open")
	}

	defer func() {
		e.fields.FD = -1
	}()

	if err := unix.Close(e.fields.FD); err != nil {
		e.logger.Error(err, "Error closing epoll FD")
	}

	return nil
}

func (e *epollFD) Field(name string) (*field.Field, error) {
	fieldContainer := reflect.ValueOf(e.fields)
	return field.ByName(name, fieldContainer)
}
