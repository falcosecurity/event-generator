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
	"fmt"
	"strings"
	"sync"

	"github.com/google/uuid"

	"github.com/falcosecurity/event-generator/pkg/alert"
	"github.com/falcosecurity/event-generator/pkg/test/loader"
	"github.com/falcosecurity/event-generator/pkg/test/tester"
)

// testImpl is an implementation of tester.Tester.
type testerImpl struct {
	alertRetriever        alert.Retriever
	testIDEnvVarPrefix    string
	testIDEnvVarPrefixLen int
	testIDIgnorePrefix    string
	testIDIgnorePrefixLen int

	sync.Mutex
	uidToAlerts map[uuid.UUID][]*alert.Alert
}

// Verify that testerImpl implements tester.Tester interface.
var _ tester.Tester = (*testerImpl)(nil)

// New creates a new tester.
func New(alertRetriever alert.Retriever, testIDEnvKey, testIDIgnorePrefix string) tester.Tester {
	testIDEnvVarPrefix := testIDEnvKey + "="
	testIDEnvVarPrefixLen := len(testIDEnvVarPrefix)
	t := &testerImpl{
		alertRetriever:        alertRetriever,
		testIDEnvVarPrefix:    testIDEnvVarPrefix,
		testIDEnvVarPrefixLen: testIDEnvVarPrefixLen,
		testIDIgnorePrefix:    testIDIgnorePrefix,
		testIDIgnorePrefixLen: len(testIDIgnorePrefix),
		uidToAlerts:           make(map[uuid.UUID][]*alert.Alert),
	}
	return t
}

func (t *testerImpl) StartAlertsCollection(ctx context.Context) error {
	alertCh, err := t.alertRetriever.AlertStream(ctx)
	if err != nil {
		return fmt.Errorf("error creating alert stream: %w", err)
	}

	alertInfoCh := t.filterAlertsWithUID(ctx, alertCh)
	t.startAlertsCaching(alertInfoCh)
	return nil
}

// alertInfo associated an alert with the corresponding test UID.
type alertInfo struct {
	uid   *uuid.UUID
	alert *alert.Alert
}

// filterAlertsWithUID asynchronously reads from the provided alerts channel and only produces, on the returned channel,
// the alerts containing a test UID.
func (t *testerImpl) filterAlertsWithUID(ctx context.Context, alertCh <-chan *alert.Alert) <-chan *alertInfo {
	alertInfoCh := make(chan *alertInfo)
	go func() {
		defer close(alertInfoCh)
		for {
			select {
			case <-ctx.Done():
				return
			case alrt, ok := <-alertCh:
				if !ok {
					return
				}

				uid := t.findUID(alrt)
				if uid == nil {
					continue
				}

				select {
				case <-ctx.Done():
				case alertInfoCh <- &alertInfo{uid: uid, alert: alrt}:
				}
			}
		}
	}()
	return alertInfoCh
}

const (
	// procEnvFieldName is the name of the alert field containing the process environment variables.
	procEnvFieldName = "proc.env"
	// uuidV4Len is the length of the UUIDv4 textual representation (see uuid.Parse implementation).
	uuidV4Len = 36
)

// findUID returns the test UID extracted from the provided alert. If test UID is not found, nil is returned.
func (t *testerImpl) findUID(alrt *alert.Alert) *uuid.UUID {
	// Retrieve the process environment variables.
	procEnv, ok := alrt.OutputFields[procEnvFieldName]
	if !ok {
		return nil
	}

	// Search for the environment variable containing the test ID.
	index := strings.Index(procEnv, t.testIDEnvVarPrefix)
	if index == -1 {
		return nil
	}

	// Strip the environment variable name and verify if the result has the ignore prefix.
	procEnv = procEnv[index+t.testIDEnvVarPrefixLen:]
	if strings.HasPrefix(procEnv, t.testIDIgnorePrefix) {
		return nil
	}

	// Parse the contained test UID.
	uid, err := uuid.Parse(procEnv[:uuidV4Len])
	if err != nil {
		return nil
	}

	return &uid
}

// startAlertsCaching starts caching the alerts received through the provided channel.
func (t *testerImpl) startAlertsCaching(alertInfoCh <-chan *alertInfo) {
	for info := range alertInfoCh {
		t.cacheAlert(info.uid, info.alert)
	}
}

// cacheAlert inserts the provided alert into the underlying cache.
func (t *testerImpl) cacheAlert(uid *uuid.UUID, alrt *alert.Alert) {
	t.Lock()
	defer t.Unlock()
	t.uidToAlerts[*uid] = append(t.uidToAlerts[*uid], alrt)
}

func (t *testerImpl) Report(uid *uuid.UUID, rule string, expectedOutcome *loader.TestExpectedOutcome) *tester.Report {
	t.Lock()
	defer t.Unlock()

	report := &tester.Report{}
	alerts, ok := t.uidToAlerts[*uid]
	if !ok {
		return report
	}

	for _, alrt := range alerts {
		accountAlert(report, rule, alrt, expectedOutcome)
	}

	return report
}

// accountAlert accounts the provided alert in the provided report, by matching it against the provided expected outcome
// for the provided rule. If the provided expected outcome is nil or empty, and the alert is generated for the requested
// rule, it is accounted as a successful match.
func accountAlert(report *tester.Report, reportRule string, alrt *alert.Alert,
	expectedOutcome *loader.TestExpectedOutcome) {
	if alrt.Rule != reportRule {
		return
	}

	// A nil expected outcome matches any alert.
	if expectedOutcome == nil {
		report.SuccessfulMatches++
		return
	}

	var fieldWarnings []tester.ReportFieldWarning

	if source := expectedOutcome.Source; source != nil && alrt.Source != *source {
		fieldWarnings = append(fieldWarnings, tester.ReportFieldWarning{
			Field:    "source",
			Expected: *source,
			Got:      alrt.Source,
		})
	}

	if hostname := expectedOutcome.Hostname; hostname != nil && alrt.Hostname != *hostname {
		fieldWarnings = append(fieldWarnings, tester.ReportFieldWarning{
			Field:    "hostname",
			Expected: *hostname,
			Got:      alrt.Hostname,
		})
	}

	if priority := expectedOutcome.Priority; priority != nil && string(alrt.Priority) != *priority {
		fieldWarnings = append(fieldWarnings, tester.ReportFieldWarning{
			Field:    "priority",
			Expected: *priority,
			Got:      alrt.Priority,
		})
	}

	for expectedKey, expectedValue := range expectedOutcome.OutputFields {
		if value, ok := alrt.OutputFields[expectedKey]; !ok || value != expectedValue {
			fieldWarnings = append(fieldWarnings, tester.ReportFieldWarning{
				Field:    expectedKey,
				Expected: expectedValue,
				Got:      value,
			})
		}
	}

	if len(fieldWarnings) > 0 {
		report.GeneratedWarnings = append(report.GeneratedWarnings, tester.ReportWarning{FieldWarnings: fieldWarnings})
		return
	}

	report.SuccessfulMatches++
}
