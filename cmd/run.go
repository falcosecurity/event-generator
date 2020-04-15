package cmd

import (
	"fmt"
	"regexp"
	"time"

	// register event collections
	_ "github.com/falcosecurity/event-generator/events/k8saudit"
	_ "github.com/falcosecurity/event-generator/events/syscall"

	"github.com/falcosecurity/event-generator/events"
	"github.com/falcosecurity/event-generator/pkg/runner"
	logger "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
)

// DefaultNamespace const contains the name of the default Kubernetes namespace.
const DefaultNamespace = "default"

// NewRun instantiates the run subcommand.
func NewRun() *cobra.Command {
	c := &cobra.Command{
		Use:   "run [regexp]",
		Short: "Run actions",
		Long: `Performs a variety of suspect actions.
Without arguments it runs all actions, otherwise only those actions matching the given regular expression.

Warning:
  This command might alter your system. For example, some actions modify files and directories below
  /bin, /etc, /dev, etc.
  Make sure you fully understand what is the purpose of this tool before running any action.
`,
		Args:              cobra.MaximumNArgs(1),
		DisableAutoGenTag: true,
	}

	flags := c.Flags()
	kubeConfigFlags := genericclioptions.NewConfigFlags(false)
	kubeConfigFlags.AddFlags(flags)
	matchVersionKubeConfigFlags := cmdutil.NewMatchVersionFlags(kubeConfigFlags)
	matchVersionKubeConfigFlags.AddFlags(flags)

	ns := flags.Lookup("namespace")
	ns.DefValue = DefaultNamespace
	ns.Value.Set(DefaultNamespace)

	var sleep time.Duration
	flags.DurationVar(&sleep, "sleep", 0, "time to sleep prior to trigger an action")

	c.RunE = func(c *cobra.Command, args []string) error {
		ns, err := flags.GetString("namespace")
		if err != nil {
			return err
		}
		l := logger.StandardLogger()

		r, err := runner.New(
			runner.WithLogger(l),
			runner.WithKubeFactory(cmdutil.NewFactory(matchVersionKubeConfigFlags)),
			runner.WithKubeNamespace(ns),
			runner.WithExecutable("", "--loglevel", l.GetLevel().String(), "run"),
			runner.WithSleep(sleep),
		)
		if err != nil {
			return err
		}

		c.SilenceUsage = true

		if len(args) == 0 {
			return r.Run(events.All())
		}

		reg, err := regexp.Compile(args[0])
		if err != nil {
			return err
		}

		evts := events.ByRegexp(reg)
		if len(evts) == 0 {
			return fmt.Errorf(`no events matching '%s'`, args[0])
		}

		return r.Run(evts)

	}

	return c
}
