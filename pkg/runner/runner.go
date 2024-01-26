// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.
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

package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/falcosecurity/event-generator/events"
	logger "github.com/sirupsen/logrus"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
)

type Runner struct {
	log     *logger.Logger
	kf      cmdutil.Factory
	kn      string
	exePath string
	exeArgs []string
	inCnt   bool
	alias   string
	sleep   time.Duration
	loop    bool
	all     bool
	quiet   bool
	plgn    Plugin
}

func (r *Runner) logEntry(ctx context.Context) *logger.Entry {
	l := r.log.WithContext(ctx)
	if r.alias != "" {
		l = l.WithField("as", r.alias)
	}
	return l
}

func (r *Runner) trigger(ctx context.Context, n string, f events.Action) (triggered bool, cleanup func(), err error) {
	fields := logger.Fields{
		"action": n,
	}
	log := r.logEntry(ctx).WithFields(fields)

	h := &helper{
		action: n,
		runner: r,
		log:    log,
	}

	if !r.all && events.Disabled(n) {
		log.Debug("action not enabled")
		return false, nil, nil
	}

	if r.kf != nil {
		h.builder = r.kf.NewBuilder().RequireNamespace()
		if r.kn != "" {
			h.builder.NamespaceParam(r.kn).DefaultNamespace()
		}
	}

	if r.plgn != nil {
		if plgnErr := r.plgn.PreRun(ctx, log, n, f); plgnErr != nil {
			return true, h.cleanup, plgnErr
		}
	}

	if r.sleep > 0 {
		h.Sleep(r.sleep)
	}

	var actErr error
	if actErr = f(h); actErr != nil {
		var skipErr *events.ErrSkipped
		if errors.As(actErr, &skipErr) {
			log.WithField("reason", skipErr.Reason).Warn("action skipped")
		} else {
			log.WithError(actErr).Error("action error")
		}
	} else if !h.hasLog && !r.quiet {
		log.Info("action executed")
	}

	if r.plgn != nil {
		if plgnErr := r.plgn.PostRun(ctx, log, n, f, actErr); plgnErr != nil {
			return true, h.cleanup, plgnErr
		}
	}

	return true, h.cleanup, nil
}

func (r *Runner) runOnce(ctx context.Context, m map[string]events.Action) (err error, shutdown bool) {

	if len(m) == 0 {
		return fmt.Errorf("no action selected"), false
	}

	var cList []func()
	teardown := func() {
		for _, c := range cList {
			c()
		}
	}
	defer teardown()

	actionsTriggered := false
	for n, f := range m {
		triggered, cleanup, err := r.trigger(ctx, n, f)
		actionsTriggered = actionsTriggered || triggered
		if cleanup != nil {
			cList = append(cList, cleanup)
		}
		if err != nil {
			return err, false
		}
		select {
		case <-ctx.Done():
			return nil, true
		default:
			continue
		}
	}

	if !actionsTriggered {
		return fmt.Errorf("none of the selected actions is enabled"), false
	}

	return nil, false
}

func (r *Runner) Run(ctx context.Context, m map[string]events.Action) (err error) {
	log := r.logEntry(ctx)
	var shutdown bool
	for err, shutdown = r.runOnce(ctx, m); r.loop && !shutdown; {
		log.Debug("restart loop")
		err, shutdown = r.runOnce(ctx, m)
	}
	if shutdown {
		log.Info("shutdown completed")
	}
	return
}

func procAlias() string {
	procPath, _ := os.Executable()
	procName := filepath.Base(procPath)
	calledAs := filepath.Base(os.Args[0])
	if procName != calledAs {
		return calledAs
	}
	return ""
}

func inContainer() bool {
	b, err := os.ReadFile("/proc/1/cmdline")
	if err != nil {
		return false
	}
	return strings.HasPrefix(string(b), os.Args[0])
}

func New(options ...Option) (*Runner, error) {
	r := &Runner{}

	if err := Options(options).Apply(r); err != nil {
		return nil, err
	}

	if r.log == nil {
		r.log = logger.New()
	}

	if r.quiet {
		r.log = &logger.Logger{
			Out:          r.log.Out,
			Hooks:        r.log.Hooks,
			Formatter:    r.log.Formatter,
			ReportCaller: r.log.ReportCaller,
			ExitFunc:     r.log.ExitFunc,
			Level:        logger.ErrorLevel,
		}
	}

	if r.exePath == "" {
		path, err := os.Executable()
		if err != nil {
			return nil, err
		}
		r.exePath = path
	}

	r.alias = procAlias()
	r.inCnt = inContainer()

	return r, nil
}

func WithLogger(l *logger.Logger) Option {
	return func(r *Runner) error {
		r.log = l
		return nil
	}
}

func WithSleep(d time.Duration) Option {
	return func(r *Runner) error {
		r.sleep = d
		return nil
	}
}

func WithLoop(loop bool) Option {
	return func(r *Runner) error {
		r.loop = loop
		return nil
	}
}

func WithKubeFactory(factory cmdutil.Factory) Option {
	return func(r *Runner) error {
		r.kf = factory
		return nil
	}
}

func WithKubeNamespace(namespace string) Option {
	return func(r *Runner) error {
		r.kn = namespace
		return nil
	}
}

func WithExecutable(path string, args ...string) Option {
	return func(r *Runner) error {
		r.exePath = path
		r.exeArgs = args
		return nil
	}
}

func WithPlugin(plugin Plugin) Option {
	return func(r *Runner) error {
		r.plgn = plugin
		return nil
	}
}

func WithAllEnabled(all bool) Option {
	return func(r *Runner) error {
		r.all = all
		return nil
	}
}

func WithQuiet(quiet bool) Option {
	return func(r *Runner) error {
		r.quiet = quiet
		return nil
	}
}
