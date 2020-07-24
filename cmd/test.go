package cmd

import (

	// register event collections
	"time"

	_ "github.com/falcosecurity/event-generator/events/k8saudit"
	_ "github.com/falcosecurity/event-generator/events/syscall"
	"github.com/falcosecurity/event-generator/pkg/runner"
	"github.com/falcosecurity/event-generator/pkg/tester"

	"github.com/spf13/cobra"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

// NewTest instantiates the test subcommand.
func NewTest() *cobra.Command {
	c, runEWithOpts := newRunTemplate()

	c.Use = "test [regexp]"
	c.Short = "Run and test actions"
	c.Long = `Performs a variety of suspect actions and test them against a running Falco instance.
Without arguments it runs all actions, otherwise only those actions matching the given regular expression.

` + runWarningMessage

	flags := c.Flags()

	var testTimeout time.Duration
	flags.DurationVar(&testTimeout, "test-timeout", tester.DefaultTestTimeout, "Test duration timeout")

	grpcCfg := grpcFlags(flags)

	c.RunE = func(c *cobra.Command, args []string) error {
		t, err := tester.New(grpcCfg, tester.WithTestTimeout(testTimeout))
		if err != nil {
			return err
		}
		return runEWithOpts(c, args, runner.WithPlugin(t))
	}

	return c
}
