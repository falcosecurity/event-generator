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
	"reflect"
	"regexp"
)

var (
	errNoTestsFound        = fmt.Errorf("no tests found")
	errUnexpectedTestsType = fmt.Errorf("unexpected tests type: must be a list")
	errUnexpectedTestType  = fmt.Errorf("unexpected test type: must be an object")
)

const (
	testsKey     = "tests"
	testCasesKey = "cases"
)

// instantiateTestTemplates returns a new raw tests description generated, from the provided one, by instantiating the
// contained test templates. A test templates is instantiated only if it contains test case specs; otherwise, it is
// included as is, like any other test, in the returned result. For each returned test, the function returns, in
// the corresponding position of the `sourceTestPositions` and `generatingTestCases` slices,
//   - its original position in the provided raw tests description, or the original position of the generating test
//     template
//   - the test case generating it, or nil, if the test was left untouched.
func instantiateTestTemplates(rawDesc map[string]any) (newRawDesc map[string]any,
	sourceTestPositions []int, generatingTestCases []TestCase, err error) {
	rawTests, ok := rawDesc[testsKey]
	if !ok {
		return nil, nil, nil, errNoTestsFound
	}

	rawTestsSlice, ok := rawTests.([]any)
	if !ok {
		return nil, nil, nil, errUnexpectedTestsType
	}

	// Instantiate each test template using the values extracted from the corresponding test cases.
	var newRawTests []any
	for rawTestIndex, rawTest := range rawTestsSlice {
		rawTestMap, ok := rawTest.(map[string]any)
		if !ok {
			return nil, nil, nil, errUnexpectedTestType
		}

		rawTestCaseSpecs, ok := rawTestMap[testCasesKey]
		if !ok {
			// The test does not specify test cases, and it's supposed to not be a template: keep it as is.
			newRawTests = append(newRawTests, rawTest)
			sourceTestPositions = append(sourceTestPositions, rawTestIndex)
			generatingTestCases = append(generatingTestCases, nil)
			continue
		}

		// Test specifies test cases. Remove test cases from test template.
		delete(rawTestMap, testCasesKey)

		// Parse test case specs to obtain the concrete test cases.
		testCases, err := parseTestCaseSpecs(rawTestCaseSpecs)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("error parsing test case specs for test at index %d: %w", rawTestIndex,
				err)
		}

		// Generate a new test for each test case.
		for testCaseIndex, testCase := range testCases {
			newRawTest, err := instantiateTestTemplate(rawTestMap, deepCopyMap(testCase))
			if err != nil {
				return nil, nil, nil, fmt.Errorf("error instantiating test template: %w", err)
			}

			newRawTest["name"] = fmt.Sprintf("%s_testCase#%d", newRawTest["name"], testCaseIndex)

			newRawTests = append(newRawTests, newRawTest)
			sourceTestPositions = append(sourceTestPositions, rawTestIndex)
		}
		generatingTestCases = append(generatingTestCases, testCases...)
	}

	newRawDesc = make(map[string]any)
	newRawDesc[testsKey] = newRawTests
	return newRawDesc, sourceTestPositions, generatingTestCases, nil
}

var noOpSetValueFunc = func(_ any) {}

// instantiateTestTemplate is a wrapper around fillTemplate generating new copies of the provided test template and test
// case before passing them to it.
func instantiateTestTemplate(testTemplate map[string]any, testCase TestCase) (map[string]any, error) {
	testTemplateCopy := deepCopyMap(testTemplate)
	testCaseCopy := deepCopyMap(testCase)
	if err := fillTemplate(testTemplateCopy, testCaseCopy, noOpSetValueFunc); err != nil {
		return nil, fmt.Errorf("error filling test template with test case values %v: %w", testCaseCopy, err)
	}

	return testTemplateCopy, nil
}

// templateParameterRegex matches any string in the form [<spaces>]%{[<spaces>]item.<keyName>[<spaces>]}[<spaces>]
// and, at the same time, enable capturing of <keyName>.
var templateParameterRegex = regexp.MustCompile(`^\s*%{\s*(\S+?)\.(\S+)\s*}\s*$`)

// fillTemplate fills each template parameter with the corresponding value taken from the provided values.
func fillTemplate(template any, values map[string]any, setValueFunc func(val any)) error {
	switch t := template.(type) {
	case map[string]any:
		// Recursively fill parameters in map values.
		for k, v := range t {
			if err := fillTemplate(v, values, func(val any) { t[k] = val }); err != nil {
				return fmt.Errorf("error filling template on key %s's value: %w", k, err)
			}
		}
	case []any:
		// Recursively fill parameters in slice values.
		for idx, v := range t {
			if err := fillTemplate(v, values, func(val any) { t[idx] = val }); err != nil {
				return fmt.Errorf("error filling template on element at index %d: %w", idx, err)
			}
		}
	case string:
		// Verify if the encountered string specifies a template parameter, and it matches a known value key.
		match := templateParameterRegex.FindStringSubmatch(t)
		if match == nil {
			return nil
		}

		if len(match) != 3 {
			panic(fmt.Sprintf("unexpected match length: expected: %d, got: %d", 3, len(match)))
		}

		if match[1] != "item" {
			return nil
		}

		valueKey := match[2]
		valToSet, ok := values[valueKey]
		if !ok {
			return fmt.Errorf("template parameter %s doesn't match any provided value key", t)
		}

		// Fill the template parameter with the found value.
		setValueFunc(valToSet)
	}
	return nil
}

// testCaseStrategy is the strategy employed by the test case to instantiate a real test.
type testCaseStrategy string

const (
	// TestCaseStrategyVector specifies that the case generates a single test description from the provided values.
	TestCaseStrategyVector testCaseStrategy = "vector"
	// TestCaseStrategyMatrix specifies that the resource generates a test description for each combination of the
	// provided values.
	TestCaseStrategyMatrix testCaseStrategy = "matrix"
)

// testCaseSpec specifies how to generate one or more test cases.
type testCaseSpec struct {
	// Strategy how Values should be interpreted in order to generate concrete test cases.
	Strategy testCaseStrategy `yaml:"strategy" mapstructure:"strategy"`
	// Values defines values that should be used to generate test cases. It is interpreted based on Strategy.
	Values map[string]any `yaml:"values" mapstructure:"values"`
}

// parseTestCaseSpecs parses the provided raw case specs and returned the corresponding concrete test cases.
func parseTestCaseSpecs(rawCaseSpecs any) ([]TestCase, error) {
	// Decode test case specs.
	var specs []*testCaseSpec
	if err := decode(rawCaseSpecs, &specs, decodeTestCaseStrategy); err != nil {
		return nil, fmt.Errorf("error decoding: %w", err)
	}

	// Generate the concrete test cases from specs. In the meantime, account for the occurrences of each key in the test
	// case specs (see later).
	// Notice: a single test case spec can generate multiple concrete test cases.
	var cases []TestCase
	keyOccurrences := make(map[string]int)
	for specIndex, spec := range specs {
		values := spec.Values
		switch strategy := spec.Strategy; strategy {
		case TestCaseStrategyVector:
			cases = append(cases, values)
			accountKeyOccurrences(keyOccurrences, values)
		case TestCaseStrategyMatrix:
			// Generate all possible combinations for the provided value lists.
			combs, err := generateCombinations(values)
			if err != nil {
				return nil, fmt.Errorf("error generating combinations for test case matrix spec at index %d: %w",
					specIndex, err)
			}

			// Generate a new test case for each combination.
			for _, comb := range combs {
				cases = append(cases, newTestCase(comb))
			}
			accountKeyOccurrences(keyOccurrences, values)
		default:
			return nil, fmt.Errorf("unknown test case strategy %q", strategy)
		}
	}

	// Verify that all test case specs specified the same set of keys.
	expectedOccurrences := 0
	for _, occurrences := range keyOccurrences {
		if expectedOccurrences == 0 {
			expectedOccurrences = occurrences
			continue
		}

		if occurrences != expectedOccurrences {
			return nil, fmt.Errorf("test cases specify heterogeneous set of keys")
		}
	}

	return cases, nil
}

// decodeTestCaseStrategy is a mapstructure.DecodeHookFunc allowing to unmarshal a testCaseStrategy.
func decodeTestCaseStrategy(fromType, toType reflect.Type, from any) (any, error) {
	if fromType.Kind() != reflect.String || toType != reflect.TypeOf(testCaseStrategy("")) {
		return from, nil
	}

	switch caseStrategy := testCaseStrategy(from.(string)); caseStrategy {
	case TestCaseStrategyVector, TestCaseStrategyMatrix:
		return caseStrategy, nil
	default:
		return nil, fmt.Errorf("unknown test case strategy %q", caseStrategy)
	}
}

// accountKeyOccurrences accounts for values' keys occurrences.
func accountKeyOccurrences(keyOccurrences map[string]int, values map[string]any) {
	for key := range values {
		keyOccurrences[key]++
	}
}

// combinationValue contains a combination value and its corresponding key.
type combinationValue struct {
	key   string
	value any
}

// combination represents a single values combination.
type combination []*combinationValue

// generateCombinations generate the list of all possible combinations of values of the provided lists.
func generateCombinations(lists map[string]any) ([]combination, error) {
	var combs []combination
	for key, list := range lists {
		values, ok := list.([]any)
		if !ok {
			return nil, fmt.Errorf("value for key %q is not a list", key)
		}

		var newCombs []combination
		for _, value := range values {
			combVal := &combinationValue{key: key, value: value}
			valCombs := combine(combVal, combs)
			newCombs = append(newCombs, valCombs...)
		}
		combs = newCombs
	}
	return combs, nil
}

// combine returns a new list of combinations generated by adding to each combination the provided value. If the
// provided list of combinations is empty, it returns a list with a single combination containing the provided value.
func combine(combValue *combinationValue, combs []combination) []combination {
	if len(combs) == 0 {
		return []combination{{combValue}}
	}

	newCombs := make([]combination, 0, len(combs))
	for _, comb := range combs {
		newComb := comb
		newComb = append(newComb, combValue)
		newCombs = append(newCombs, newComb)
	}
	return newCombs
}

// newTestCase creates a new test case from the provided combination of values.
func newTestCase(comb combination) TestCase {
	testCase := make(TestCase, len(comb))
	for _, combVal := range comb {
		testCase[combVal.key] = combVal.value
	}
	return testCase
}

// deepCopyMap returns a deep copy of the provided generic map.
func deepCopyMap(m map[string]any) map[string]any {
	cp := make(map[string]any)
	for key, value := range m {
		switch v := value.(type) {
		case map[string]any:
			cp[key] = deepCopyMap(v)
		case []any:
			cp[key] = deepCopySlice(v)
		default:
			cp[key] = value
		}
	}
	return cp
}

// deepCopySlice returns a deep copy of the provided generic slice.
func deepCopySlice(s []any) []any {
	cp := make([]any, len(s))
	for i, value := range s {
		switch v := value.(type) {
		case map[string]any:
			cp[i] = deepCopyMap(v)
		case []any:
			cp[i] = deepCopySlice(v)
		default:
			cp[i] = value
		}
	}
	return cp
}
