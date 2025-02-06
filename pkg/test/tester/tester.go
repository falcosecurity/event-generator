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

package tester

import (
	"context"

	"github.com/google/uuid"

	"github.com/falcosecurity/event-generator/pkg/test/loader"
)

// Tester allows to verify that the running tests produce the expected outcomes.
type Tester interface {
	// StartAlertsCollection starts the process of alerts collection.
	StartAlertsCollection(ctx context.Context) error
	// Report returns a report containing information regarding the alerts matching or not matching the provided
	// expected outcome for the provided rule. A nil or empty expected outcome matches any alert corresponding to the
	// provided rule.
	Report(uid *uuid.UUID, rule string, expectedOutcome *loader.TestExpectedOutcome) *Report
}

// A Report contains information regarding the successful matches and generated warning for given test testing a given
// rule.
type Report struct {
	TestName          string          `json:"test" yaml:"test"`
	RuleName          string          `json:"-" yaml:"-"`
	SuccessfulMatches int             `json:"successfulMatches" yaml:"successfulMatches"`
	GeneratedWarnings []ReportWarning `json:"generatedWarnings,omitempty" yaml:"generatedWarnings,omitempty"`
}

// Empty reports if the report specifies no successful matches and no generated warning.
func (r *Report) Empty() bool {
	return r.SuccessfulMatches == 0 && len(r.GeneratedWarnings) == 0
}

// A ReportWarning is associated to a received alert matching a rule, but having some fields not matching the expected
// outcome definition.
type ReportWarning struct {
	FieldWarnings []ReportFieldWarning `json:"fieldWarnings,omitempty" yaml:"fieldWarnings,omitempty"`
}

// ReportFieldWarning contains information regarding an expected outcome field, its expected value and the value
// contained in the alert.
type ReportFieldWarning struct {
	Field    string `json:"field" yaml:"field"`
	Expected any    `json:"expected" yaml:"expected"`
	Got      any    `json:"got" yaml:"got"`
}
