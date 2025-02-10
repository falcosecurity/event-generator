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

package textencoder

import (
	"fmt"
	"io"
	"strings"

	"github.com/falcosecurity/event-generator/pkg/test/tester"
)

// textEncoder is an implementation of tester.ReportEncoder allowing to write a report to the underlying destination
// using a formatted text encoding.
type textEncoder struct {
	writer io.Writer
}

// Verify that textEncoder implements tester.ReportEncoder interface.
var _ tester.ReportEncoder = (*textEncoder)(nil)

// New creates a new report text-formatting encoder.
func New(w io.Writer) tester.ReportEncoder {
	te := &textEncoder{writer: w}
	return te
}

func (te *textEncoder) Encode(report *tester.Report) error {
	sb := strings.Builder{}
	sb.WriteString(fmt.Sprintf("Test %s, Rule %s\n", report.TestName, report.RuleName))

	if report.Empty() {
		sb.WriteString("\tFailed\n")
		_, err := io.WriteString(te.writer, sb.String())
		return err
	}

	sb.WriteString(fmt.Sprintf("\tSuccessful matches: %d\n", report.SuccessfulMatches))
	sb.WriteString(fmt.Sprintf("\tGenerated warnings: %d\n", len(report.GeneratedWarnings)))

	for warningIndex := range report.GeneratedWarnings {
		warning := &report.GeneratedWarnings[warningIndex]
		sb.WriteString(fmt.Sprintf("\t\tWarning %d\n", warningIndex))
		for fieldWarningIndex := range warning.FieldWarnings {
			fieldWarning := &warning.FieldWarnings[fieldWarningIndex]
			sb.WriteString(fmt.Sprintf("\t\t\tField: %s, Expected: %v, Got: %v\n", fieldWarning.Field,
				fieldWarning.Expected, fieldWarning.Got))
		}
	}

	_, err := io.WriteString(te.writer, sb.String())
	return err
}
