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

package counter

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/procfs"
	logger "github.com/sirupsen/logrus"

	"github.com/falcosecurity/event-generator/events"
	"github.com/falcosecurity/event-generator/pkg/alert"
)

type stat struct {
	actual   uint64
	expected uint64
}

// Counter is a plugin that
type Counter struct {
	i        uint64
	sleep    int64
	loop     bool
	humanize bool
	dryRun   bool
	log      *logger.Logger
	ticker   *time.Ticker
	tickD    time.Duration
	lastT    time.Time
	proc     *procfs.Proc
	lastS    *procfs.ProcStat
	actions  []string
	list     map[string]*stat
	sync.RWMutex
}

// New returns a new Counter instance.
func New(ctx context.Context, alertRetriever alert.Retriever, options ...Option) (*Counter, error) {
	cntr := &Counter{}
	if err := Options(options).Apply(cntr); err != nil {
		return nil, err
	}

	if cntr.log == nil {
		cntr.log = logger.New()
	}

	cntr.list = make(map[string]*stat, len(cntr.actions))
	for _, n := range cntr.actions {
		cntr.list[n] = &stat{}
	}

	if !cntr.dryRun {
		alertCh, err := alertRetriever.AlertStream(ctx)
		if err != nil {
			return nil, fmt.Errorf("error creating alert stream: %w", err)
		}
		go cntr.watcher(ctx, alertCh)
	}

	if cntr.tickD > 0 {
		go cntr.clock(ctx, cntr.tickD)
	}

	return cntr, nil
}

func (c *Counter) watcher(ctx context.Context, alertCh <-chan *alert.Alert) {
	for {
		select {
		case <-ctx.Done():
			return
		case alrt, ok := <-alertCh:
			if !ok {
				return
			}
			for n := range c.list {
				if events.MatchRule(n, alrt.Rule) {
					s := c.list[n]
					atomic.AddUint64(&s.actual, 1)
					break
				}
			}
		}
	}
}

func (c *Counter) clock(ctx context.Context, d time.Duration) {
	c.ticker = time.NewTicker(d)
	c.lastT = time.Now()
	running := true
	round := 1
	logEntry := c.log.WithField("sleep", time.Duration(c.sleep))
	if c.dryRun {
		logEntry = logEntry.WithField("dry-run", true)
	}
	logEntry.Infof("round #%d", round)
	for {
		select {
		case t := <-c.ticker.C:
			if running {
				// round completed, rest for a while before collecting stats
				c.Lock()
				c.log.Info("resting...")
			} else {
				// collecting stats (while still locked)
				c.logStats()
				c.reset(t)

				// start a new round
				c.Unlock()
				round++
				c.log.Info("") // empty line for improved readability
				logEntry.WithField("sleep", time.Duration(c.sleep)).Infof("round #%d", round)
			}
			running = !running
		case <-ctx.Done():
			c.ticker.Stop()
			if !running {
				c.Unlock()
			}
			return
		}
	}
}

func (c *Counter) reset(t time.Time) {

	c.lastT = t
	c.i = 0

	dirty := false
	invalid := false
	for n, s := range c.list {
		ac, ex := atomic.LoadUint64(&s.actual), atomic.LoadUint64(&s.expected)
		atomic.StoreUint64(&s.expected, 0)
		atomic.StoreUint64(&s.actual, 0)

		dirty = dirty || ac > ex
		if ex == 0 {
			invalid = true
			c.log.WithField("action", n).
				Warn("cannot generate events")
		}
	}

	if invalid {
		c.log.Warn("some actions may be too slow, consider to use different actions")
	}

	if dirty {
		c.log.Warnf("unexpected events received, retrying with sleep=%s", time.Duration(c.sleep).String())
	}

	if c.loop && !dirty && c.sleep > 0 {
		c.sleep = c.sleep / 2
	}
}

func (c *Counter) PreRun(ctx context.Context, log *logger.Entry, n string, f events.Action) (err error) {
	c.Lock()
	c.i++
	sleep := c.sleep
	c.Unlock()

	if sleep > 0 {
		time.Sleep(time.Duration(sleep))
	}
	return nil
}

func (c *Counter) PostRun(ctx context.Context, log *logger.Entry, n string, f events.Action, actErr error) error {
	if s, ok := c.list[n]; ok {
		atomic.AddUint64(&s.expected, 1)
	}
	return nil
}

func WithLogger(l *logger.Logger) Option {
	return func(c *Counter) error {
		c.log = l
		return nil
	}
}

func WithActions(actions map[string]events.Action) Option {
	return func(c *Counter) error {
		c.actions = make([]string, len(actions))
		i := 0
		for n := range actions {
			c.actions[i] = n
			i++
		}
		return nil
	}
}

func WithLoop(loop bool) Option {
	return func(c *Counter) error {
		c.loop = loop
		return nil
	}
}

func WithSleep(sleep time.Duration) Option {
	return func(c *Counter) error {
		c.sleep = int64(sleep)
		return nil
	}
}

func WithRoundDuration(duration time.Duration) Option {
	return func(c *Counter) error {
		c.tickD = duration
		return nil
	}
}

func WithPid(pid int) Option {
	return func(c *Counter) error {
		proc, err := procfs.NewProc(pid)
		if err != nil {
			return err
		}
		c.proc = &proc
		procStat, err := c.proc.Stat()
		if err != nil {
			return err
		}
		c.lastS = &procStat
		return nil
	}
}

func WithHumanize(humanize bool) Option {
	return func(c *Counter) error {
		c.humanize = humanize
		return nil
	}
}

func WithDryRun(dryRun bool) Option {
	return func(c *Counter) error {
		c.dryRun = dryRun
		return nil
	}
}
