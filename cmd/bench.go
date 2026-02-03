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

package cmd

import (
	"errors"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	logger "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/falcosecurity/event-generator/cmd/internal/alertretriever"
	"github.com/falcosecurity/event-generator/pkg/counter"
	"github.com/falcosecurity/event-generator/pkg/runner"
)

var errRoundDurationMustBeLongerThanSleep = errors.New("--round-duration must be longer than --sleep")

// NewBench instantiates the bench subcommand.
func NewBench() *cobra.Command {
	c, runEWithOpts := newRunTemplate()

	c.Use = "bench [regexp]"
	c.Short = "Benchmark for Falco"
	c.Long = `Benchmark a running Falco instance.

This command generates a high number of Event Per Second (EPS), to test the events throughput allowed by Falco.
The number of EPS is controlled by the "--sleep" option: reduce the sleeping duration to increase the EPS.
If the "--loop" option is set, the sleeping duration is halved on each round.
The "--pid" option can be used to monitor the Falco process.
	
N.B.:
	- the Falco HTTP Output must be enabled to use this command
	- "outputs.rate" and "outputs.max_burst" values within the Falco configuration must be increased,
	  otherwise EPS will be rate-limited by the throttling mechanism
	- since not all actions can be used for benchmarking,
	  only those actions matching the given regular expression are used

One commmon way to use this command is as following:

	event-generator bench "ChangeThreadNamespace|ReadSensitiveFileUntrusted" --all --loop --sleep 10ms --pid $(pidof -s falco)


` + runWarningMessage

	c.Args = cobra.ExactArgs(1)

	flags := c.Flags()

	var pid int
	flags.IntVar(&pid, "pid", 0, "A process PID to monitor while benchmarking (e.g. the falco process)")
	var roundDuration time.Duration
	flags.DurationVar(&roundDuration, "round-duration", time.Second*5, "Duration of a benchmark round")
	var humanize bool
	flags.BoolVar(&humanize, "humanize", true, "Humanize values when printing statistics")
	var dryRun bool
	flags.BoolVar(&dryRun, "dry-run", false, "Do not expose an HTTP server for Falco HTTP Output")

	alertRetrieverConfig := alertretriever.Config{}
	alertRetrieverConfig.InitCommandFlags(c)

	counterLogger := logger.StandardLogger()

	c.RunE = func(c *cobra.Command, args []string) error {
		ctx := c.Context()
		mainLogger, err := logr.FromContext(ctx)
		if err != nil {
			panic(fmt.Sprintf("logger unconfigured: %v", err))
		}

		evts, err := parseEventsArg(args[0])
		if err != nil {
			return err
		}

		loop, err := flags.GetBool("loop")
		if err != nil {
			return err
		}

		sleep, err := flags.GetDuration("sleep")
		if err != nil {
			return err
		}

		if roundDuration <= sleep {
			return errRoundDurationMustBeLongerThanSleep
		}

		alertRetriever, err := alertRetrieverConfig.Build(mainLogger)
		if err != nil {
			return fmt.Errorf("error building alert retriever: %w", err)
		}

		alertCh, err := alertRetriever.AlertStream(ctx)
		if err != nil {
			return fmt.Errorf("error creating alert stream: %w", err)
		}

		opts := append([]counter.Option(nil),
			counter.WithActions(evts),
			counter.WithLogger(counterLogger),
			counter.WithLoop(loop),
			counter.WithSleep(sleep),
			counter.WithRoundDuration(roundDuration),
			counter.WithHumanize(humanize),
			counter.WithDryRun(dryRun),
		)
		if pid != 0 {
			opts = append(opts, counter.WithPid(pid))
		}
		p, err := counter.New(ctx, alertCh, opts...)
		if err != nil {
			return err
		}

		return runEWithOpts(c, args,
			runner.WithPlugin(p),
			// override runner options:
			runner.WithQuiet(true),             // reduce runner verbosity
			runner.WithSleep(time.Duration(0)), // no sleep, since sleeping will be controlled by the plugin
			runner.WithLoop(true),              // always loop
		)
	}

	return c
}
