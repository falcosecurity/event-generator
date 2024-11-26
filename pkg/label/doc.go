// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 The Falco Authors
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

// Package label provides support for parsing a set of supported labels from a comma-separated list of values in the
// form <labelX>=<labelXValue>. The Set container is used to store the supported labels. A Set can be serialized (using
// the pre-defined aforementioned comma-separated format) and written to a generic destination through the Set.Write
// method.
package label
