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

	"github.com/go-logr/logr"

	"github.com/falcosecurity/event-generator/pkg/test"
	"github.com/falcosecurity/event-generator/pkg/test/loader"
	"github.com/falcosecurity/event-generator/pkg/test/resource"
	"github.com/falcosecurity/event-generator/pkg/test/script/shell"
	"github.com/falcosecurity/event-generator/pkg/test/step"
	testimpl "github.com/falcosecurity/event-generator/pkg/test/test"
)

// builder is an implementation of test.Builder.
type builder struct {
	stepBuilder     step.Builder
	resourceBuilder resource.Builder
}

// Verify that builder implements test.Builder interface.
var _ test.Builder = (*builder)(nil)

// New creates a new builder.
func New(resourceBuilder resource.Builder, stepBuilder step.Builder) (test.Builder, error) {
	if resourceBuilder == nil {
		return nil, fmt.Errorf("test resource builder must not be nil")
	}

	if stepBuilder == nil {
		return nil, fmt.Errorf("test step builder must not be nil")
	}

	b := &builder{
		resourceBuilder: resourceBuilder,
		stepBuilder:     stepBuilder,
	}
	return b, nil
}

func (b *builder) Build(logger logr.Logger, testDesc *loader.Test) (test.Test, error) {
	// Create a unique test script from "before" and "after" scripts.
	testScript := shell.New(logger, testDesc.BeforeScript, testDesc.AfterScript)

	// Build test resources.
	resourcesNum := len(testDesc.Resources)
	testResources := make([]resource.Resource, 0, resourcesNum)
	for resourceIndex := 0; resourceIndex < resourcesNum; resourceIndex++ {
		rawResource := &testDesc.Resources[resourceIndex]
		logger := logger.WithValues("resourceIndex", resourceIndex)
		testResource, err := b.resourceBuilder.Build(logger, rawResource)
		if err != nil {
			return nil, &test.ResourceBuildError{ResourceName: rawResource.Name, ResourceIndex: resourceIndex, Err: err}
		}

		testResources = append(testResources, testResource)
	}

	// Build test steps.
	stepsNum := len(testDesc.Steps)
	testSteps := make([]step.Step, 0, stepsNum)
	for stepIndex := 0; stepIndex < stepsNum; stepIndex++ {
		rawStep := &testDesc.Steps[stepIndex]
		testStep, err := b.stepBuilder.Build(rawStep)
		if err != nil {
			return nil, &test.StepBuildError{StepName: rawStep.Name, StepIndex: stepIndex, Err: err}
		}

		testSteps = append(testSteps, testStep)
	}

	t := testimpl.New(logger, testScript, testResources, testSteps)
	return t, nil
}
