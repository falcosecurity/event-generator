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

package builder

import (
	"fmt"

	"github.com/falcosecurity/event-generator/pkg/test"
	"github.com/falcosecurity/event-generator/pkg/test/loader"
	"github.com/falcosecurity/event-generator/pkg/test/runner"
	"github.com/falcosecurity/event-generator/pkg/test/runner/host"
)

// builder is an implementation of runner.Builder.
type builder struct {
	// testBuilder is the builder used to build a test.
	testBuilder test.Builder
}

// Verify that builder implements runner.Builder interface.
var _ runner.Builder = (*builder)(nil)

// New creates a new builder.
func New(testBuilder test.Builder) (runner.Builder, error) {
	if testBuilder == nil {
		return nil, fmt.Errorf("test builder must not be nil")
	}

	b := &builder{testBuilder: testBuilder}
	return b, nil
}

func (b *builder) Build(description *runner.Description) (runner.Runner, error) {
	runnerType := description.Type
	logger := description.Logger.WithValues("runnerType", runnerType)
	switch runnerType {
	case loader.TestRunnerTypeHost:
		return host.New(
			logger,
			b.testBuilder,
			description.Environ,
			description.TestConfigEnvKey,
			description.ProcIDEnvKey,
			description.ProcID,
		)
	default:
		return nil, fmt.Errorf("unknown test runner type %q", runnerType)
	}
}
