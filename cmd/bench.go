package cmd

import (
	"errors"
	"time"

	"github.com/falcosecurity/event-generator/pkg/counter"
	"github.com/falcosecurity/event-generator/pkg/runner"

	logger "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var roundDurationMustBeLongerThanSleepErr = errors.New("--round-duration must be longer than --sleep")

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
The easiest way to get the PID is by appending the following snippet:
--pid $(ps -ef | awk '$8=="falco" {print $2}')
	
N.B.:
	- the Falco gRPC Output must be enabled to use this command
	- also, you may need to increase the "outputs.rate" and "outputs.max_burst" values within the Falco configuration,
	otherwise EPS will be rate-limited by the throttling mechanism.
	
Since not all actions can be used for benchmarking, only those actions matching the given regular expression are used.

` + runWarningMessage

	c.Args = cobra.ExactArgs(1)

	flags := c.Flags()

	var pid int
	flags.IntVar(&pid, "pid", 0, "A process PID to monitor while benchmarking (e.g. the falco process)")
	var roundDuration time.Duration
	flags.DurationVar(&roundDuration, "round-duration", time.Second*2, "Duration of a benchmark round")
	var pollingTimeout time.Duration
	flags.DurationVar(&pollingTimeout, "polling-interval", time.Millisecond*100, "Duration of gRPC APIs polling timeout")

	grpcCfg := grpcFlags(flags)

	l := logger.StandardLogger()

	c.RunE = func(c *cobra.Command, args []string) error {

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
			return roundDurationMustBeLongerThanSleepErr
		}

		opts := append([]counter.Option(nil),
			counter.WithActions(evts),
			counter.WithLogger(l),
			counter.WithLoop(loop),
			counter.WithSleep(sleep),
			counter.WithRoundDuration(roundDuration),
			counter.WithPollingTimeout(pollingTimeout),
		)
		if pid != 0 {
			opts = append(opts, counter.WithPid(pid))
		}
		p, err := counter.New(c.Context(), grpcCfg, opts...)
		if err != nil {
			return err
		}

		return runEWithOpts(c, args,
			runner.WithPlugin(p),
			// override runner options:
			runner.WithQuiet(true),             // reduce runner verbosity
			runner.WithSleep(time.Duration(0)), // no sleep, since sleeping will be controled by the plugin
			runner.WithLoop(true),              // always loop
		)
	}

	return c
}
