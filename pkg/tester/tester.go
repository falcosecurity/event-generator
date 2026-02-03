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

package tester

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	logger "github.com/sirupsen/logrus"

	"github.com/falcosecurity/event-generator/events"
	"github.com/falcosecurity/event-generator/pkg/alert"
)

// ErrFailed is returned when a test fails
var ErrFailed = errors.New("test failed")

const DefaultTestTimeout = time.Minute

// Tester is a plugin that tests the action outcome in a running Falco instance via the HTTP Output.
type Tester struct {
	timeout time.Duration

	sync.Mutex
	alertsCache []*alert.Alert
}

// New returns a new Tester instance.
func New(alertCh <-chan *alert.Alert, options ...Option) (*Tester, error) {
	t := &Tester{timeout: DefaultTestTimeout}
	if err := Options(options).Apply(t); err != nil {
		return nil, err
	}

	go t.startAlertsCaching(alertCh)
	return t, nil
}

// startAlertsCaching starts caching the alertsCache received through the provided channel.
func (t *Tester) startAlertsCaching(alertCh <-chan *alert.Alert) {
	for alrt := range alertCh {
		t.cacheAlert(alrt)
	}
}

// cacheAlert inserts the provided alert into the underlying cache.
func (t *Tester) cacheAlert(alrt *alert.Alert) {
	t.Lock()
	defer t.Unlock()
	t.alertsCache = append(t.alertsCache, alrt)
}

// PreRun should run before action execution.
func (t *Tester) PreRun(context.Context, *logger.Entry, string, events.Action) (err error) {
	t.emptyAlertsCache()
	return nil
}

func (t *Tester) emptyAlertsCache() {
	t.Lock()
	defer t.Unlock()
	t.alertsCache = []*alert.Alert{}
}

// PostRun should run after action execution.
func (t *Tester) PostRun(ctx context.Context, log *logger.Entry, n string, _ events.Action, actErr error) error {
	if strings.HasPrefix(n, "helper.") {
		log.Info("test skipped for helpers")
		return nil
	}

	if actErr != nil {
		var skipErr *events.ErrSkipped
		if errors.As(actErr, &skipErr) {
			return nil // test skipped
		}
		return ErrFailed
	}

	innerCtx, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()

	for {
		if err := innerCtx.Err(); err != nil {
			return err
		}

		if t.checkMatchingAlertPresenceAndDoEmptyCache(n) {
			return nil
		}

		// Wait some time before checking again.
		time.Sleep(50 * time.Millisecond)
	}
}

// checkMatchingAlertPresenceAndDoEmptyCache checks that an alert matching actionName is present in the alerts cache and
// returns a boolean indicating its presence. Whatever is the results, it empties the alerts cache.
func (t *Tester) checkMatchingAlertPresenceAndDoEmptyCache(actionName string) bool {
	t.Lock()
	defer t.Unlock()

	alertFound := false

	for _, alrt := range t.alertsCache {
		if events.MatchRule(actionName, alrt.Rule) {
			logger.WithField("rule", alrt.Rule).WithField("source", alrt.Source).Info("test passed")
			alertFound = true
			break
		}
		logger.WithField("rule", alrt.Rule).WithField("source", alrt.Source).Debug("event skipped")
	}

	t.alertsCache = []*alert.Alert{}
	return alertFound
}

func WithTestTimeout(timeout time.Duration) Option {
	return func(t *Tester) error {
		t.timeout = timeout
		return nil
	}
}
