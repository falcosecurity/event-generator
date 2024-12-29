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

// Package suite provides the definition of a test suite as well as a mechanism to load multiple test suites from
// multiple sources.
// A Suite is uniquely associated with a rule: each loaded test is associated with a specific Suite, depending on the
// rule name it specifies on its description. If the user didn't specify any rule name in the test description, the test
// is associated with the test suite corresponding to NoRuleNamePlaceholder.
// The Loader can be used to load multiple test suites from multiple sources. Loader.Load accepts Source objects; a
// Source is a named io.Reader, and can be created from files or from readers using the function NewSourceFromFile or
// NewSourceFromReader, respectively.
package suite
