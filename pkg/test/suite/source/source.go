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

package source

import (
	"io"

	"github.com/falcosecurity/event-generator/pkg/test/suite"
)

// source is a suite.Source implementation.
type source struct {
	name   string
	reader io.Reader
}

// Verify that source implements the suite.Source interface.
var _ suite.Source = (*source)(nil)

func (s *source) Name() string {
	return s.name
}

func (s *source) Read(p []byte) (int, error) {
	return s.reader.Read(p)
}

// New creates a new suite.Source from the provided reader with the provided name.
func New(name string, r io.Reader) suite.Source {
	return &source{name: name, reader: r}
}
