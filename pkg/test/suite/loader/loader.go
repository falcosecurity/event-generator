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

package loader

import (
	"fmt"

	testloader "github.com/falcosecurity/event-generator/pkg/test/loader"
	"github.com/falcosecurity/event-generator/pkg/test/suite"
)

// loader is a suite.Loader implementation.
type loader struct {
	// descLoader is used to load a tests description from a single source.
	descLoader *testloader.Loader
	// canLoadTestsWithNoRuleName indicates if tests with absent or empty rule name are allowed to be loaded.
	canLoadTestsWithNoRuleName bool
	// loadedTestSuites is the list of all loaded test suites.
	loadedTestSuites []*suite.Suite
	// loadedTestSuiteIndexes takes note of the index, in loadedTestSuites, of each loaded test suite (used for fast
	// lookup).
	loadedTestSuiteIndexes map[string]int
}

// Verify that loader implements the suite.Loader interface.
var _ suite.Loader = (*loader)(nil)

// New creates a new test suite loader.
func New(descLoader *testloader.Loader, canLoadTestsWithNoRuleName bool) suite.Loader {
	l := &loader{
		descLoader:                 descLoader,
		canLoadTestsWithNoRuleName: canLoadTestsWithNoRuleName,
		loadedTestSuiteIndexes:     make(map[string]int),
	}
	return l
}

func (l *loader) Load(source suite.Source) error {
	// Load all tests from the provided list of sources and group them by rule name.
	desc, err := l.descLoader.Load(source)
	if err != nil {
		return fmt.Errorf("error loading description: %w", err)
	}

	// Associate each loaded test to the proper test suite based on the specified rule name.
	sourceName := source.Name()
	for testIndex := range desc.Tests {
		testDesc := &desc.Tests[testIndex]
		ruleName := getRuleName(testDesc)
		// Return an error if it is not allowed to load tests with absent/empty rule name and the test is not compliant
		// with it.
		if !l.canLoadTestsWithNoRuleName && ruleName == suite.NoRuleNamePlaceholder {
			return &suite.NoRuleNameError{
				TestName:        testDesc.Name,
				TestSourceName:  sourceName,
				TestSourceIndex: testDesc.SourceIndex,
			}
		}

		var testSuite *suite.Suite
		// Verify if we discovered a new test suite or not. If a new test suite is discovered, take note of its
		// index in the returned slice to easily find the test suite a test belongs to.
		testSuiteIndex, ok := l.loadedTestSuiteIndexes[ruleName]
		if !ok {
			// Found new test suite.
			testSuite = &suite.Suite{RuleName: ruleName}
			l.loadedTestSuites = append(l.loadedTestSuites, testSuite)
			l.loadedTestSuiteIndexes[ruleName] = len(l.loadedTestSuites) - 1
		} else {
			// Test suite already exists.
			testSuite = l.loadedTestSuites[testSuiteIndex]
		}
		testInfo := &suite.TestInfo{SourceName: sourceName, Test: testDesc}
		testSuite.TestsInfo = append(testSuite.TestsInfo, testInfo)
	}

	// Validate each test suite.
	for _, testSuite := range l.loadedTestSuites {
		if err := validateTestNamesUniqueness(testSuite); err != nil {
			return fmt.Errorf("error validating test suite %q's test names uniqueness: %w", testSuite.RuleName, err)
		}
	}

	return nil
}

// getRuleName returns the name of the rule associated with the provided test description.
func getRuleName(testDesc *testloader.Test) string {
	if ruleName := testDesc.Rule; ruleName != nil && *ruleName != "" {
		return *ruleName
	}

	return suite.NoRuleNamePlaceholder
}

// validateTestNamesUniqueness verifies that each suite's test has a unique name.
func validateTestNamesUniqueness(testSuite *suite.Suite) error {
	testsInfo := make(map[string]*suite.TestInfo, len(testSuite.TestsInfo))
	for _, testInfo1 := range testSuite.TestsInfo {
		name := testInfo1.Test.Name
		if testInfo2, ok := testsInfo[name]; ok {
			return fmt.Errorf("%s and %s have the same name %q", testInfoToString(testInfo1),
				testInfoToString(testInfo2), name)
		}
		testsInfo[name] = testInfo1
	}
	return nil
}

// testInfoToString returns a stringified representation of the provided test info.
func testInfoToString(testInfo *suite.TestInfo) string {
	var testCase string
	if len(testInfo.Test.OriginatingTestCase) > 0 {
		testCase = ", testCase: \""
		for k, v := range testInfo.Test.OriginatingTestCase {
			testCase += fmt.Sprintf("%s=%v,", k, v)
		}
		testCase = testCase[:len(testCase)-1] + "\""
	}
	return fmt.Sprintf("test (source: %s, index: %d%s)", testInfo.SourceName, testInfo.Test.SourceIndex, testCase)
}

func (l *loader) Get() []*suite.Suite {
	testSuites := l.loadedTestSuites
	l.loadedTestSuites = nil
	l.loadedTestSuiteIndexes = make(map[string]int)
	return testSuites
}
