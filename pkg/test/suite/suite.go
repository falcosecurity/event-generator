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

package suite

import (
	"fmt"
	"io"

	"github.com/falcosecurity/event-generator/pkg/test/loader"
	"github.com/falcosecurity/event-generator/pkg/test/tester"
)

// Source represents a test suite source. It is an io.Reader owning a name.
type Source interface {
	// Name returns the name associated to the source.
	Name() string
	io.Reader
}

// TestInfo wraps a test and provides additional information to it, such as the name of the source it belongs and its
// index within the source.
type TestInfo struct {
	// SourceName is the name of the source the test belongs.
	SourceName string
	// Test is the wrapped test.
	Test *loader.Test
}

// Suite represents a test suite for a specific rule.
type Suite struct {
	// RuleName is the name of the rule the tests are associated with.
	RuleName string
	// TestsInfo contains the list of tests belonging to the suite.
	TestsInfo []*TestInfo
}

// Loader allows to load multiple test suites from multiple sources.
type Loader interface {
	// Load loads the test suites from the provided source into the Loader instance. Load can be called multiple times
	// with different sources. Call Get to obtain the list of all loaded test suites. If an error is generated, the
	// Loader instance internal state remains undefined.
	Load(source Source) error
	// Get returns the list of all loaded test suites. After the call, the internal state of the loaded is re-set to a
	// clean (initial) state.
	Get() []*Suite
}

// NoRuleNameError represents an error occurring when is not allowed to load tests with absent or empty rule name and a
// test doesn't specify it.
type NoRuleNameError struct {
	TestName        string
	TestSourceName  string
	TestSourceIndex int
}

func (e *NoRuleNameError) Error() string {
	// Does not include source name as this error type is meant to be used while loading a single source through
	// Loader.Load.
	return fmt.Sprintf("error loading test %q at index %d: absent or empty rule name", e.TestName, e.TestSourceIndex)
}

// NoRuleNamePlaceholder is the value given to the rule name field of a test not specifying any value for it.
// Notice: whe choose the empty string as it is not a valid rule name.
const NoRuleNamePlaceholder = ""

// A Report contains test reports for all tests belonging to a test suite.
type Report struct {
	TestSuiteName string           `json:"suite" yaml:"suite"`
	TestReports   []*tester.Report `json:"testReports" yaml:"testReports"`
}

// ReportEncoder allows to encode a report.
type ReportEncoder interface {
	// Encode encodes the provided report with a specific format and write it to the underlying destination.
	Encode(report *Report) error
}
