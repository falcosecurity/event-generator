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

package runner

import (
	"context"

	"github.com/go-logr/logr"

	"github.com/falcosecurity/event-generator/pkg/baggage"
	"github.com/falcosecurity/event-generator/pkg/test/loader"
)

// Runner allows to run a test.
type Runner interface {
	// Run runs the provided test.
	Run(ctx context.Context, testID string, test *loader.Test) error
}

// Builder allows to build a new test runner.
type Builder interface {
	// Build builds a new test runner using the provided description.
	Build(runnerType loader.TestRunnerType, logger logr.Logger, description *Description) (Runner, error)
}

// Description contains information to build a new test runner.
type Description struct {
	// Environ is a list of strings representing the environment, in the form "key=value".
	Environ []string
	// TestDescriptionEnvKey is the key identifying the environment variable used to store the serialized test
	// description.
	TestDescriptionEnvKey string
	// TestDescriptionFileEnvKey is the key identifying the environment variable used to store path of the file
	// containing the serialized test description.
	TestDescriptionFileEnvKey string
	// TestIDEnvKey is the key identifying the environment variable used to store the test identifier in the form
	// [<ignorePrefix>]<testUID>.
	TestIDEnvKey string
	// TestIDIgnorePrefix is the optional testID prefix value.
	TestIDIgnorePrefix string
	// BaggageEnvKey is the key identifying the environment variable used to store the baggage.
	BaggageEnvKey string
	// Baggage is the process baggage.
	Baggage *baggage.Baggage
}
