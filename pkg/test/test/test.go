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

package test

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"

	"github.com/falcosecurity/event-generator/pkg/test"
	"github.com/falcosecurity/event-generator/pkg/test/field"
	"github.com/falcosecurity/event-generator/pkg/test/resource"
	"github.com/falcosecurity/event-generator/pkg/test/step"
)

// testImpl is an implementation of test.Test.
type testImpl struct {
	logger    logr.Logger
	script    test.Script
	resources []resource.Resource
	steps     []step.Step
}

// Verify that testImpl implements test.Test interface.
var _ test.Test = (*testImpl)(nil)

// New creates a new test.
func New(logger logr.Logger, script test.Script, resources []resource.Resource, steps []step.Step) test.Test {
	t := &testImpl{
		logger:    logger,
		script:    script,
		resources: resources,
		steps:     steps,
	}
	return t
}

func (t *testImpl) Run(ctx context.Context) error {
	// Run before script.
	runAfterScript, err := t.script.RunBefore(ctx)
	if err != nil {
		return fmt.Errorf("error running before script: %w", err)
	}

	// Create resources.
	testResources, err := t.createResources(ctx)
	resourcesCreatedNum := len(testResources)
	if err != nil {
		if err := runAfterScript(ctx); err != nil {
			t.logger.Error(err, "Error running after script")
		}
		t.destroyResources(ctx, resourcesCreatedNum)
		return err
	}

	// Run steps.
	testsRunNum, err := t.runSteps(ctx, testResources)

	// Cleanup.
	t.cleanupSteps(ctx, testsRunNum)
	t.destroyResources(ctx, resourcesCreatedNum)

	// Run after script.
	if err := runAfterScript(ctx); err != nil {
		t.logger.Error(err, "Error running after script")
	}

	return err
}

// createResources creates all the configured test resources. It returns the set of created resources. If an error
// occurs, the returned set of created resources will contain less resources than configured.
func (t *testImpl) createResources(ctx context.Context) (map[string]resource.Resource, error) {
	testResources := make(map[string]resource.Resource, len(t.resources))
	for resourceIndex, testResource := range t.resources {
		resourceName := testResource.Name()
		if err := testResource.Create(ctx); err != nil {
			return testResources, &test.ResourceCreationError{ResourceName: resourceName,
				ResourceIndex: resourceIndex, Err: fmt.Errorf("error creating resource: %w", err)}
		}

		testResources[resourceName] = testResource
		t.logger.V(1).Info("Created resource", "resourceName", resourceName, "resourceIndex", resourceIndex)
	}

	return testResources, nil
}

// destroyResources destroys the first resourceCreatedNum resources.
func (t *testImpl) destroyResources(ctx context.Context, resourcesCreatedNum int) {
	for resourceIndex := resourcesCreatedNum - 1; resourceIndex >= 0; resourceIndex-- {
		testResource := t.resources[resourceIndex]
		resourceName := testResource.Name()
		logger := t.logger.WithValues("resourceName", resourceName, "resourceIndex", resourceIndex)
		if err := testResource.Destroy(ctx); err != nil {
			logger.Error(err, "Error destroying resource")
		} else {
			logger.V(1).Info("Destroyed resource")
		}
	}
}

// runSteps runs the configured steps. The provided testResources are used to resolve steps field bindings. It returns
// the number of steps successfully run (this number could be less than the configured ones, if an error occurs).
func (t *testImpl) runSteps(ctx context.Context, testResources map[string]resource.Resource) (int, error) {
	// Every time a step is successfully run, it is accounted into precedingSteps: this is done in order to enable
	// field bindings resolution for the subsequent steps.
	precedingSteps := make(map[string]step.Step, len(t.steps))
	for stepIndex, testStep := range t.steps {
		stepName := testStep.Name()
		bindings, err := getStepBindings(testStep, testResources, precedingSteps)
		if err != nil {
			return stepIndex, &test.StepRunError{StepName: stepName, StepIndex: stepIndex,
				Err: fmt.Errorf("error retrieving bindings: %w", err)}
		}

		if err := testStep.Bind(bindings); err != nil {
			return stepIndex, &test.StepRunError{StepName: stepName, StepIndex: stepIndex,
				Err: fmt.Errorf("error performing bindings: %w", err)}
		}

		if err := testStep.Run(ctx); err != nil {
			return stepIndex, &test.StepRunError{StepName: stepName, StepIndex: stepIndex,
				Err: fmt.Errorf("error running step: %w", err)}
		}

		precedingSteps[stepName] = testStep
		t.logger.V(1).Info("Executed test step", "stepName", stepName, "stepIndex", stepIndex)
	}

	return len(t.steps), nil
}

// getStepBindings returns the testStep bindings, resolving them by searching in the provided testResources and
// precedingSteps.
func getStepBindings(testStep step.Step, testResources map[string]resource.Resource,
	precedingSteps map[string]step.Step) ([]*step.Binding, error) {
	var bindings []*step.Binding
	for _, fieldBinding := range testStep.FieldBindings() {
		srcName := fieldBinding.SrcName
		var fieldRetriever field.Retriever
		if srcResource, ok := testResources[srcName]; ok {
			fieldRetriever = srcResource
		} else if srcStep, ok := precedingSteps[srcName]; ok {
			fieldRetriever = srcStep
		}
		if fieldRetriever == nil {
			return nil, fmt.Errorf("no source %q found in resources or preceding steps", srcName)
		}

		srcFieldName := fieldBinding.SrcField
		srcField, err := fieldRetriever.Field(srcFieldName)
		if err != nil {
			return nil, fmt.Errorf("no resource/preceding step field %q.%q found", srcName, srcFieldName)
		}

		binding := &step.Binding{LocalField: fieldBinding.LocalField, SrcField: srcField}
		bindings = append(bindings, binding)
	}

	return bindings, nil
}

// cleanupSteps executes cleanup for the first testsRunNum steps.
func (t *testImpl) cleanupSteps(ctx context.Context, testsRunNum int) {
	for stepIndex := testsRunNum - 1; stepIndex >= 0; stepIndex-- {
		testStep := t.steps[stepIndex]
		stepName := testStep.Name()
		logger := t.logger.WithValues("stepName", stepName, "stepIndex", stepIndex)
		if err := testStep.Cleanup(ctx); err != nil {
			t.logger.Error(err, "Error executing test step cleanup")
		} else {
			logger.V(1).Info("Executed test step cleanup")
		}
	}
}
