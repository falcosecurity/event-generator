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
	"os"

	"github.com/falcosecurity/event-generator/pkg/test/loader"
)

// TestInfo wraps a test and provides additional information to it, such as the name of the source it belongs and its
// index within the source.
type TestInfo struct {
	// SourceName is the name of the source the test belongs.
	SourceName string
	// Index is the index of the test within the source.
	Index int
	// Test is the wrapped test.
	Test *loader.Test
}

func (t *TestInfo) string() string {
	return fmt.Sprintf("test (source: %s, index: %d)", t.SourceName, t.Index)
}

// Suite represents a test suite for a specific rule.
type Suite struct {
	// RuleName is the name of the rule the tests are associated with.
	RuleName string
	// TestsInfo contains the list of tests belonging to the suite.
	TestsInfo []*TestInfo
}

// validateTestNamesUniqueness verifies that each suite's test has a unique name.
func (s *Suite) validateTestNamesUniqueness() error {
	testsInfo := make(map[string]*TestInfo, len(s.TestsInfo))
	for _, testInfo1 := range s.TestsInfo {
		name := testInfo1.Test.Name
		if testInfo2, ok := testsInfo[name]; ok {
			return fmt.Errorf("%s and %s have the same name %q", testInfo1.string(), testInfo2.string(), name)
		}
		testsInfo[name] = testInfo1
	}
	return nil
}

// Source is an io.Reader owning a name.
type Source interface {
	// Name returns the name associated to the source.
	Name() string
	io.Reader
}

// source is a Source implementation.
type source struct {
	name   string
	reader io.Reader
}

// Verify that source implements the Source interface.
var _ Source = (*source)(nil)

func (s *source) Name() string {
	return s.name
}

func (s *source) Read(p []byte) (int, error) {
	return s.reader.Read(p)
}

// NewSourceFromFile creates a new Source from the provided file.
func NewSourceFromFile(file *os.File) Source {
	return &source{name: file.Name(), reader: file}
}

// NewSourceFromReader creates a new Source from the provided reader with the provided name.
func NewSourceFromReader(name string, r io.Reader) Source {
	return &source{name: name, reader: r}
}

// Loader loads test suites.
type Loader struct {
	// descLoader is used to load a tests description from a single source.
	descLoader *loader.Loader
}

// NewLoader creates a new test suite loader.
func NewLoader(descLoader *loader.Loader) *Loader {
	sl := &Loader{descLoader: descLoader}
	return sl
}

var errSourcesCannotBeEmpty = fmt.Errorf("source list cannot be empty")

// Load loads the test suites from the provided sources. The test suites are returned in their appearing order among all
// the provided sources.
func (l *Loader) Load(sources []Source) ([]*Suite, error) {
	if len(sources) == 0 {
		return nil, errSourcesCannotBeEmpty
	}

	// Load all tests from the provided list of sources and group them by rule name.
	var suites []*Suite
	suiteIndexes := make(map[string]int)
	for _, source := range sources {
		sourceName := source.Name()
		desc, err := l.descLoader.Load(source)
		if err != nil {
			return nil, fmt.Errorf("error loading description from source %q: %w", sourceName, err)
		}

		// Associate each loaded test to the proper test suite based on the specified rule name.
		for testIndex := range desc.Tests {
			testDesc := &desc.Tests[testIndex]
			ruleName := getRuleName(testDesc)
			var suite *Suite
			// Verify if we discovered a new test suite or not. If a new test suite is discovered, take note of its
			// index in the returned slice to easily find the test suite a test belongs to.
			suiteIndex, ok := suiteIndexes[ruleName]
			if !ok {
				// Found new test suite.
				suite = &Suite{RuleName: ruleName}
				suites = append(suites, suite)
				suiteIndexes[ruleName] = len(suites) - 1
			} else {
				// Test suite already exists.
				suite = suites[suiteIndex]
			}
			testInfo := &TestInfo{
				SourceName: sourceName,
				Index:      testIndex,
				Test:       testDesc,
			}
			suite.TestsInfo = append(suite.TestsInfo, testInfo)
		}
	}

	// Validate each test suite.
	for ruleName, suite := range suites {
		if err := suite.validateTestNamesUniqueness(); err != nil {
			return nil, fmt.Errorf("error validating test suite %q's test names uniqueness: %w", ruleName, err)
		}
	}

	return suites, nil
}

// NoRuleNamePlaceholder is the value given to the rule name field of a test not specifying any value for it.
// Notice: whe choose the empty string as it is not a valid rule name.
const NoRuleNamePlaceholder = ""

// getRuleName returns the name of the rule associated with the provided test description.
func getRuleName(testDesc *loader.Test) string {
	ruleName := testDesc.Rule
	if ruleName != nil {
		return *ruleName
	}

	// The empty string is used to identify
	return NoRuleNamePlaceholder
}
