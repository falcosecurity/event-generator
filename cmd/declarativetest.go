// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/falcosecurity/event-generator/pkg/tester"
	logger "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// NewDeclarative instantiates the declarative subcommand for test command.
func NewDeclarativeTest() *cobra.Command {
	c := &cobra.Command{
		Use:   "declarative [yaml-file-path]",
		Short: "Execute and test Falco rules using a declarative approach",
		Long: `This command takes the path to a YAML file as an argument. 
		The YAML file defines tests that are parsed and executed, 
		and checks if specific Falco rules are triggered.`,
		Args:              cobra.MaximumNArgs(1),
		DisableAutoGenTag: true,
	}

	var testTimeout time.Duration
	flags := c.Flags()
	flags.DurationVar(&testTimeout, "test-timeout", tester.DefaultTestTimeout, "Test duration timeout")

	grpcCfg := grpcFlags(flags)

	c.RunE = func(c *cobra.Command, args []string) error {
		t, err := tester.New(grpcCfg, tester.WithTestTimeout(testTimeout))
		if err != nil {
			return err
		}

		tests, err := parseYamlFile(args[0])
		if err != nil {
			return err
		}

		var failedTests []error // stores the errors of failed tests

		// Execute each test in the YAML file
		for _, eachTest := range tests.Tests {
			// Execute the test steps
			err := runTestSteps(eachTest)
			if err != nil {
				failedTests = append(failedTests, fmt.Errorf("test %v failed with err: %v", eachTest.Rule, err))
				continue
			}

			// Prepare the logger
			log := logger.WithField("test", eachTest.Rule)

			// Test if the Falco rule is triggered
			err = t.PostRun(context.Background(), log, "declarative."+eachTest.Rule, nil, nil)
			if err != nil {
				failedTests = append(failedTests, fmt.Errorf("falco rule %v did not trigger as expected: %v", eachTest.Rule, err))
			}
		}

		// Print all errors
		if len(failedTests) > 0 {
			for _, ft := range failedTests {
				fmt.Println(ft)
			}
			return fmt.Errorf("some tests failed, see previous logs")
		}

		return nil
	}

	return c
}
