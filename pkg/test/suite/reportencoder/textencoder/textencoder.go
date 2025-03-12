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

	"github.com/falcosecurity/event-generator/pkg/test/suite"
	"github.com/falcosecurity/event-generator/pkg/test/tester"
)

// textEncoder is an implementation of suite.ReportEncoder allowing to write a report to the underlying destination
// using a formatted text encoding.
type textEncoder struct {
	writer io.Writer
}

// Verify that textEncoder implements suite.ReportEncoder interface.
var _ suite.ReportEncoder = (*textEncoder)(nil)

// New creates a new report text-formatting encoder.
func New(w io.Writer) suite.ReportEncoder {
	te := &textEncoder{writer: w}
	return te
}

func (te *textEncoder) Encode(report *suite.Report) error {
	sb := &strings.Builder{}
	writeFormatted(sb, "Test Suite: %s\n", report.TestSuiteName)
	const padding = "   "

	for _, testReport := range report.TestReports {
		te.encodeTestReport(sb, testReport, padding)
	}

	_, err := io.WriteString(te.writer, sb.String())
	return err
}

func (te *textEncoder) encodeTestReport(sb *strings.Builder, report *tester.Report, basePadding string) {
	padding := basePadding
	writeFormatted(sb, "%sTest: %s%s\n", padding, report.TestName, formatTestCase(report.OriginatingTestCase))

	padding += basePadding
	if report.Empty() {
		writeFormatted(sb, "%sFailed\n\n", padding)
		return
	}

	writeFormatted(sb, "%sSuccessful matches: %d\n", padding, report.SuccessfulMatches)
	writeFormatted(sb, "%sGenerated warnings: %d\n", padding, len(report.GeneratedWarnings))

	padding += basePadding
	for warningIndex := range report.GeneratedWarnings {
		warning := &report.GeneratedWarnings[warningIndex]
		writeFormatted(sb, "%sWarning %d\n", padding, warningIndex)
		padding := padding + basePadding
		for fieldWarningIndex := range warning.FieldWarnings {
			fieldWarning := &warning.FieldWarnings[fieldWarningIndex]
			writeFormatted(sb, "%sField: %s, Expected: %v, Got: %v\n", padding, fieldWarning.Field,
				fieldWarning.Expected, fieldWarning.Got)
		}
	}

	writeFormatted(sb, "\n")
}

// writeFormatted is a wrapper around fmt.Fprintf ignoring the returned values.
func writeFormatted(w io.Writer, format string, a ...any) {
	_, _ = fmt.Fprintf(w, format, a...)
}

// formatTestCase returns a formatted version of the provided test case.
func formatTestCase(testCase map[string]any) string {
	var s string
	for k, v := range testCase {
		s += fmt.Sprintf("%s=%q, ", k, v)
	}
	if s != "" {
		s = s[:len(s)-2]
		s = " (" + s + ")"
	}
	return s
}
