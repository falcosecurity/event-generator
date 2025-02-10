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

package signal

import (
	"context"
	"fmt"
	"reflect"

	"github.com/go-logr/logr"
	"golang.org/x/sys/unix"

	"github.com/falcosecurity/event-generator/pkg/test/field"
	"github.com/falcosecurity/event-generator/pkg/test/resource"
)

// signalFD implements a signal FD resource.
type signalFD struct {
	logger logr.Logger
	// resourceName is the fd resource name.
	resourceName string
	// fields defines the information exposed by signalFD for binding.
	fields struct {
		// FD is the signal file descriptor. If the resource has not been Create'd yet, or it has been Destroy'ed, FD is
		// set to -1.
		FD int `field_type:"fd"`
	}
}

// Verify that signalFD implements resource.Resource interface.
var _ resource.Resource = (*signalFD)(nil)

// New creates a new signal FD resource.
func New(logger logr.Logger, resourceName string) resource.Resource {
	s := &signalFD{
		logger:       logger,
		resourceName: resourceName,
	}
	s.fields.FD = -1
	return s
}

func (s *signalFD) Name() string {
	return s.resourceName
}

// Create creates a signal file descriptor and exposes it.
func (s *signalFD) Create(_ context.Context) error {
	if s.fields.FD != -1 {
		return fmt.Errorf("signal FD is already open")
	}

	fd, err := createSignalFD()
	if err != nil {
		return fmt.Errorf("error creating signal FD: %w", err)
	}

	s.fields.FD = fd
	return nil
}

// createSignalFD creates a new signal file descriptor and returns it.
func createSignalFD() (int, error) {
	fd, err := unix.Signalfd(-1, &unix.Sigset_t{}, 0)
	if err != nil {
		return 0, err
	}

	return fd, nil
}

// Destroy closes the exposed file descriptor.
func (s *signalFD) Destroy(_ context.Context) error {
	if s.fields.FD == -1 {
		return fmt.Errorf("signal FD is not open")
	}

	defer func() {
		s.fields.FD = -1
	}()

	if err := unix.Close(s.fields.FD); err != nil {
		s.logger.Error(err, "Error closing signal FD")
	}

	return nil
}

func (s *signalFD) Field(name string) (*field.Field, error) {
	fieldContainer := reflect.ValueOf(s.fields)
	return field.ByName(name, fieldContainer)
}
