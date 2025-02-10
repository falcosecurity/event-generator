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

package resource

import (
	"context"

	"github.com/go-logr/logr"

	"github.com/falcosecurity/event-generator/pkg/test/field"
	"github.com/falcosecurity/event-generator/pkg/test/loader"
)

// Resource represents a single resource in a test.
type Resource interface {
	// Name returns the resource name.
	Name() string
	// Create creates the resource.
	Create(ctx context.Context) error
	// Destroy destroys the resource.
	Destroy(ctx context.Context) error
	field.Retriever
}

// Builder allows to build new test resource.
type Builder interface {
	// Build builds a new test resource.
	// TODO: replace loader.TestResource with a dedicated type.
	Build(logger logr.Logger, testResource *loader.TestResource) (Resource, error)
}
