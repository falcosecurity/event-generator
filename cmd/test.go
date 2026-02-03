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

package cmd

import (
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"github.com/spf13/cobra"

	"github.com/falcosecurity/event-generator/cmd/internal/alertretriever"
	"github.com/falcosecurity/event-generator/pkg/runner"
	"github.com/falcosecurity/event-generator/pkg/tester"
)

// NewTest instantiates the test subcommand.
func NewTest() *cobra.Command {
	c, runEWithOpts := newRunTemplate()

	c.Use = "test [regexp]"
	c.Short = "Run and test actions"
	c.Long = `Performs a variety of suspect actions and test them against a running Falco instance.

Note that the Falco HTTP Output must be enabled to use this command.
Without arguments it tests all actions, otherwise only those actions matching the given regular expression.

` + runWarningMessage

	flags := c.Flags()

	var testTimeout time.Duration
	flags.DurationVar(&testTimeout, "test-timeout", tester.DefaultTestTimeout, "Test duration timeout")

	alertRetrieverConfig := alertretriever.Config{}
	alertRetrieverConfig.InitCommandFlags(c)

	c.RunE = func(c *cobra.Command, args []string) error {
		ctx := c.Context()
		mainLogger, err := logr.FromContext(ctx)
		if err != nil {
			panic(fmt.Sprintf("logger unconfigured: %v", err))
		}

		alertRetriever, err := alertRetrieverConfig.Build(mainLogger)
		if err != nil {
			return fmt.Errorf("failed to build alert retriever: %w", err)
		}

		t, err := tester.New(alertRetriever, tester.WithTestTimeout(testTimeout))
		if err != nil {
			return err
		}
		return runEWithOpts(c, args, runner.WithPlugin(t))
	}

	return c
}
