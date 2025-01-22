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

package baggage

import (
	"io"
	"strings"

	"github.com/goccy/go-yaml"
)

// Baggage stores values for the supported key-value pairs.
type Baggage struct {
	TestSuiteName   string         `yaml:"testSuiteName"`
	TestName        string         `yaml:"testName"`
	TestSourceName  string         `yaml:"testSourceName"`
	TestSourceIndex int            `yaml:"testSourceIndex"`
	TestCase        map[string]any `yaml:"testCase,omitempty"`
	// ProcIndex is set to -1 for the root process.
	ProcIndex          int    `yaml:"procIndex"`
	IsContainer        bool   `yaml:"isContainer,omitempty"`
	ContainerImageName string `yaml:"containerImageName,omitempty"`
	ContainerName      string `yaml:"containerName,omitempty"`
}

// Write writes the key-value pairs to the provided writer.
func (b *Baggage) Write(w io.Writer) error {
	return yaml.NewEncoder(w).Encode(b)
}

// Clone creates and returns a clone of the baggage.
func (b *Baggage) Clone() *Baggage {
	baggage := &Baggage{
		TestSuiteName:      b.TestSuiteName,
		TestName:           b.TestName,
		TestSourceName:     b.TestSourceName,
		TestSourceIndex:    b.TestSourceIndex,
		TestCase:           b.TestCase, // We use an assignment because we don't expect it to be modified.
		ProcIndex:          b.ProcIndex,
		IsContainer:        b.IsContainer,
		ContainerImageName: b.ContainerImageName,
		ContainerName:      b.ContainerName,
	}
	return baggage
}

// NewFromString parses the key-value pairs encoded in the provided string and returns the parsed baggage. If an empty
// string is provided, the function returns nil.
func NewFromString(baggage string) (*Baggage, error) {
	if baggage == "" {
		return nil, nil
	}

	b := &Baggage{ProcIndex: -1}
	if err := yaml.NewDecoder(strings.NewReader(baggage)).Decode(b); err != nil {
		return nil, err
	}

	return b, nil
}
