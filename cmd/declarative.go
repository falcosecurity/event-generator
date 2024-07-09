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
	"fmt"

	"github.com/falcosecurity/event-generator/pkg/declarative"
	"github.com/spf13/cobra"
)

// NewDeclarative instantiates the declarative subcommand for run command.
func NewDeclarative() *cobra.Command {
	c := &cobra.Command{
		Use:   "declarative [yaml-file-path]",
		Short: "Execute Falco tests using a declarative approach",
		Long: `This command takes the path to a YAML file as an argument. 
		The YAML file defines tests that are parsed and executed which 
		triggers specific Falco rules.`,
		Args:              cobra.MaximumNArgs(1),
		DisableAutoGenTag: true,
	}

	c.RunE = func(c *cobra.Command, args []string) error {
		tests, err := parseYamlFile(args[0])
		if err != nil {
			return err
		}

		var failedTests []error // stores the errors of failed tests

		// Execute each test mentioned in yaml file
		for _, eachTest := range tests.Tests {
			err := runTestSteps(eachTest)
			if err != nil {
				// Collect the errors if any test fails
				failedTests = append(failedTests, fmt.Errorf("test %v failed with err: %v", eachTest.Rule, err))
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

// runTestSteps executes the steps, before and after scripts defined in the test.
func runTestSteps(test declarative.Test) error {
	var runner declarative.Runner

	// Assign a runner based on test.Runner value
	switch test.Runner {
	case "HostRunner":
		runner = &declarative.Hostrunner{}
	case "ContainerRunner":
		// spawn an alpine container
		runner = &declarative.Containerrunner{Image: "alpine"}
	default:
		return fmt.Errorf("unsupported runner: %v", test.Runner)
	}

	// Execute the "Before" script.
	if err := runner.Setup(test.Before); err != nil {
		return err
	}

	// Execute each step in the test.
	for _, step := range test.Steps {
		err := runner.ExecuteStep(step)
		if err != nil {
			return fmt.Errorf("error executing steps for the rule %v : %v", test.Rule, err)
		}
	}

	// Execute the "After" script.
	if err := runner.Cleanup(test.After); err != nil {
		return err
	}
	return nil
}
