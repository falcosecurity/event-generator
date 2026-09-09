// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The Falco Authors
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
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// matrixTemplate is a test template whose matrix case spec has four keys of two values each, so it must expand to
// sixteen distinct test cases.
const matrixTemplate = `
tests:
  - name: matrix_template
    description: "four-key matrix"
    runner: HostRunner
    steps:
      - type: syscall
        name: w1
        syscall: write
        args:
          fd: 1
          buffer: "%{ item.a }"
    cases:
      - strategy: matrix
        values:
          a: ["a1", "a2"]
          b: ["b1", "b2"]
          c: ["c1", "c2"]
          d: ["d1", "d2"]
`

// TestMatrixCaseStrategyGeneratesDistinctCases verifies that a matrix case spec expands to the full cartesian product.
// Combinations used to be built by appending to a slice the caller kept using, so once a combination had spare
// capacity the siblings derived from it shared a backing array and the last value written won. The count of generated
// tests stayed right, which is what made it quiet: sixteen tests were emitted but only eight of them differed.
func TestMatrixCaseStrategyGeneratesDistinctCases(t *testing.T) {
	desc, err := New(nil, nil).Load(strings.NewReader(matrixTemplate))
	require.NoError(t, err)
	require.Len(t, desc.Tests, 16)

	seen := make(map[string]int, len(desc.Tests))
	for _, test := range desc.Tests {
		testCase := test.OriginatingTestCase
		require.Len(t, testCase, 4)
		keys := make([]string, 0, len(testCase))
		for key := range testCase {
			keys = append(keys, key)
		}
		sort.Strings(keys)

		var sb strings.Builder
		for _, key := range keys {
			fmt.Fprintf(&sb, "%s=%v,", key, testCase[key])
		}
		seen[sb.String()]++
	}

	assert.Len(t, seen, 16, "matrix expansion produced %d distinct combinations out of 16 tests: %v", len(seen), seen)
}
