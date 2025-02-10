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

package yamlencoder

import (
	"io"

	"gopkg.in/yaml.v3"

	"github.com/falcosecurity/event-generator/pkg/test/tester"
)

// yamlEncoder is an implementation of tester.ReportEncoder allowing to write a report to the underlying destination
// using a YAML encoding.
type yamlEncoder struct {
	writer io.Writer
}

// Verify that yamlEncoder implements tester.ReportEncoder interface.
var _ tester.ReportEncoder = (*yamlEncoder)(nil)

// New creates a new report JSON encoder.
func New(w io.Writer) tester.ReportEncoder {
	ye := &yamlEncoder{writer: w}
	return ye
}

func (ye *yamlEncoder) Encode(report *tester.Report) error {
	encoder := yaml.NewEncoder(ye.writer)
	return encoder.Encode(report)
}
