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

// Package field defines a generic way to reference and assign values to any test field by leveraging reflection and
// struct field tagging. Struct field tagging is used to check for semantic assignability. A source field is assignable
// to a destination field if the following two condition applies:
// - source field go type is assignable and/or convertible to destination field go type
// - source field is semantically assignable to destination field
// "Semantically assignable" means that both fields have the same `field_type`. A `field_type` must be assigned to a
// field via struct field tagging.
package field
