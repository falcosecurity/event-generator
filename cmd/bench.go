package cmd

import (

	// register event collections

	"time"

	_ "github.com/falcosecurity/event-generator/events/k8saudit"
	_ "github.com/falcosecurity/event-generator/events/syscall"
	"github.com/falcosecurity/event-generator/pkg/counter"
	"github.com/falcosecurity/event-generator/pkg/runner"

	logger "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

// NewBench instantiates the bench subcommand.
func NewBench() *cobra.Command {
	c, runEWithOpts := newRunTemplate()

	c.Use = "bench [regexp]"
	c.Short = "Benchmark actions"
	c.Long = `
Without arguments it runs all actions, otherwise only those actions matching the given regular expression.

` + runWarningMessage

	flags := c.Flags()

	var pid int
	flags.IntVar(&pid, "pid", 0, "A process PID to monitor while benchmarking (e.g. the falco process)")
	var statsInterval time.Duration
	flags.DurationVar(&statsInterval, "stats-interval", time.Second*2, "Output statistics every <stats-interval> duration")

	grpcCfg := grpcFlags(flags)

	l := logger.StandardLogger()

	c.RunE = func(c *cobra.Command, args []string) error {

		evts, err := parseEventsArg(args[0])
		if err != nil {
			return err
		}

		opts := append(make(counter.Options, 0),
			counter.WithActions(evts),
			counter.WithLogger(l),
			counter.WithStatsInterval(statsInterval),
		)
		if pid != 0 {
			opts = append(opts, counter.WithPid(pid))
		}
		p, err := counter.New(c.Context(), grpcCfg, opts...)
		if err != nil {
			return err
		}

		return runEWithOpts(c, args, runner.WithPlugin(p), runner.WithQuiet(true))
	}

	return c
}
