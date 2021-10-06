package cmd

import (
	"errors"
	"time"

	"github.com/falcosecurity/event-generator/pkg/counter"
	"github.com/falcosecurity/event-generator/pkg/runner"

	logger "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
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
	- the Falco gRPC Output must be enabled to use this command
	- "outputs.rate" and "outputs.max_burst" values within the Falco configuration must be increased,
	  otherwise EPS will be rate-limited by the throttling mechanism
	- since not all actions can be used for benchmarking, 
	  only those actions matching the given regular expression are used

One commmon way to use this command is as following:

	event-generator bench "ChangeThreadNamespace|ReadSensitiveFileUntrusted" --loop --sleep 10ms --pid $(pidof -s falco) 


` + runWarningMessage

	c.Args = cobra.ExactArgs(1)

	flags := c.Flags()

	var pid int
	flags.IntVar(&pid, "pid", 0, "A process PID to monitor while benchmarking (e.g. the falco process)")
	var roundDuration time.Duration
	flags.DurationVar(&roundDuration, "round-duration", time.Second*5, "Duration of a benchmark round")
	var pollingTimeout time.Duration
	flags.DurationVar(&pollingTimeout, "polling-interval", time.Millisecond*100, "Duration of gRPC APIs polling timeout")
	var humanize bool
	flags.BoolVar(&humanize, "humanize", true, "Humanize values when printing statistics")
	var dryRun bool
	flags.BoolVar(&dryRun, "dry-run", false, "Do not connect to Falco gRPC API")

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
			return errRoundDurationMustBeLongerThanSleep
		}

		opts := append([]counter.Option(nil),
			counter.WithActions(evts),
			counter.WithLogger(l),
			counter.WithLoop(loop),
			counter.WithSleep(sleep),
			counter.WithRoundDuration(roundDuration),
			counter.WithPollingTimeout(pollingTimeout),
			counter.WithHumanize(humanize),
			counter.WithDryRun(dryRun),
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
			runner.WithSleep(time.Duration(0)), // no sleep, since sleeping will be controlled by the plugin
			runner.WithLoop(true),              // always loop
		)
	}

	return c
}
