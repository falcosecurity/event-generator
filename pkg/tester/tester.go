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
	"fmt"
	"strings"
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
	timeout        time.Duration
	alertRetriever alert.Retriever
}

// New returns a new Tester instance.
func New(alertRetriever alert.Retriever, options ...Option) (*Tester, error) {
	t := &Tester{
		timeout:        DefaultTestTimeout,
		alertRetriever: alertRetriever,
	}
	if err := Options(options).Apply(t); err != nil {
		return nil, err
	}
	return t, nil
}

func (t *Tester) PreRun(ctx context.Context, log *logger.Entry, n string, f events.Action) (err error) {
	return nil
}

func (t *Tester) PostRun(ctx context.Context, log *logger.Entry, n string, f events.Action, actErr error) error {
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

	alertCh, err := t.alertRetriever.AlertStream(ctx)
	if err != nil {
		return fmt.Errorf("error creating alert stream: %w", err)
	}

	ctxWithTimeout, cancelTimeout := context.WithTimeout(ctx, t.timeout)
	defer cancelTimeout()

	testCtx, testCtxCancel := context.WithCancel(ctxWithTimeout)
	defer testCtxCancel()

	for {
		select {
		case <-testCtx.Done():
			return testCtx.Err()
		case alrt, ok := <-alertCh:
			if !ok {
				return fmt.Errorf("alert channel closed before getting any alert")
			}
			if events.MatchRule(n, alrt.Rule) {
				logger.WithField("rule", alrt.Rule).WithField("source", alrt.Source).Info("test passed")
				return nil
			} else {
				logger.WithField("rule", alrt.Rule).WithField("source", alrt.Source).Debug("event skipped")
			}
		}
	}
}

func WithTestTimeout(timeout time.Duration) Option {
	return func(t *Tester) error {
		t.timeout = timeout
		return nil
	}
}
