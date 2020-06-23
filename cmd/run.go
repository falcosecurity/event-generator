package cmd

import (
	"fmt"
	"regexp"
	"time"

	// register event collections
	_ "github.com/falcosecurity/event-generator/events/k8saudit"
	_ "github.com/falcosecurity/event-generator/events/syscall"

	"k8s.io/cli-runtime/pkg/genericclioptions"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"

	// Initialize all k8s client auth plugins
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"github.com/falcosecurity/event-generator/events"
	"github.com/falcosecurity/event-generator/pkg/runner"
	logger "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// DefaultNamespace const contains the name of the default Kubernetes namespace.
const DefaultNamespace = "default"

const runWarningMessage = `
Warning:
  This command might alter your system. For example, some actions modify files and directories below
  /bin, /etc, /dev, etc.
  Make sure you fully understand what is the purpose of this tool before running any action.
`

// NewRun instantiates the run subcommand.
func NewRun() *cobra.Command {
	c, runEWithOpts := newRunTemplate()
	c.RunE = func(c *cobra.Command, args []string) error {
		return runEWithOpts(c, args)
	}
	return c
}

func newRunTemplate() (c *cobra.Command, runE func(c *cobra.Command, args []string, options ...runner.Option) error) {
	c = &cobra.Command{
		Use:   "run [regexp]",
		Short: "Run actions",
		Long: `Performs a variety of suspect actions.
Without arguments it runs all actions, otherwise only those actions matching the given regular expression.

` + runWarningMessage,
		Args:              cobra.MaximumNArgs(1),
		DisableAutoGenTag: true,
	}

	flags := c.Flags()

	flags.Duration("sleep", time.Second, "The length of time to wait before running an action. Non-zero values should contain a corresponding time unit (e.g. 1s, 2m, 3h). A value of zero means no sleep.")
	flags.Bool("loop", false, "Run in a loop")

	kubeConfigFlags := genericclioptions.NewConfigFlags(false)
	kubeConfigFlags.AddFlags(flags)
	matchVersionKubeConfigFlags := cmdutil.NewMatchVersionFlags(kubeConfigFlags)
	matchVersionKubeConfigFlags.AddFlags(flags)

	ns := flags.Lookup("namespace")
	ns.DefValue = DefaultNamespace
	ns.Value.Set(DefaultNamespace)

	return c, func(c *cobra.Command, args []string, options ...runner.Option) error {

		flags := c.Flags()
		ns, err := flags.GetString("namespace")
		if err != nil {
			return err
		}
		sleep, err := flags.GetDuration("sleep")
		if err != nil {
			return err
		}
		loop, err := flags.GetBool("loop")
		if err != nil {
			return err
		}

		l := logger.StandardLogger()

		options = append(options,
			runner.WithLogger(l),
			runner.WithKubeNamespace(ns),
			runner.WithKubeFactory(cmdutil.NewFactory(matchVersionKubeConfigFlags)),
			// todo(leogr): inherit other flags
			runner.WithExecutable("", "--loglevel", l.GetLevel().String(), "run"),
			runner.WithSleep(sleep),
			runner.WithLoop(loop),
		)

		r, err := runner.New(options...)
		if err != nil {
			return err
		}

		c.SilenceUsage = true

		if len(args) == 0 {
			return r.Run(c.Context(), events.All())
		}

		reg, err := regexp.Compile(args[0])
		if err != nil {
			return err
		}

		evts := events.ByRegexp(reg)
		if len(evts) == 0 {
			return fmt.Errorf(`no events matching '%s'`, args[0])
		}

		return r.Run(c.Context(), evts)
	}
}
