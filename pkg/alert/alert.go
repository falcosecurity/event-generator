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

package alert

import (
	"context"
)

// Retriever allows to retrieve a stream of Falco alerts.
type Retriever interface {
	// AlertStream returns a channel that can be used to consume a stream of Falco alerts. The returned channel is
	// closed if the provided context is canceled.
	AlertStream(ctx context.Context) (<-chan *Alert, error)
}

// Alert is a Falco alert.
type Alert struct {
	Priority     Priority
	Rule         string
	OutputFields map[string]string
	Hostname     string
	Source       string
}

// Priority is priority associated with an alert.
type Priority string

const (
	// PriorityEmergency defines the emergency priority value.
	PriorityEmergency Priority = "emergency"
	// PriorityAlert defines the alert priority value.
	PriorityAlert Priority = "alert"
	// PriorityCritical defines the critical priority value.
	PriorityCritical Priority = "critical"
	// PriorityError defines the error priority value.
	PriorityError Priority = "error"
	// PriorityWarning defines the warning priority value.
	PriorityWarning Priority = "warning"
	// PriorityNotice defines the notice priority value.
	PriorityNotice Priority = "notice"
	// PriorityInformational defines the informational priority value.
	PriorityInformational Priority = "informational"
	// PriorityDebug defines the debug priority value.
	PriorityDebug Priority = "debug"
)
