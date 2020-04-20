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
	_ "k8s.io/client-go/plugin/pkg/client/auth"
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

	sleep := time.Second
	flags.DurationVar(&sleep, "sleep", sleep, "The length of time to wait before running an action. Non-zero values should contain a corresponding time unit (e.g. 1s, 2m, 3h). A value of zero means no sleep.")

	var loop bool
	flags.BoolVar(&loop, "loop", false, "Run in a loop")

	c.RunE = func(c *cobra.Command, args []string) error {
		ns, err := flags.GetString("namespace")
		if err != nil {
			return err
		}
		l := logger.StandardLogger()

		r, err := runner.New(
			runner.WithContext(c.Context()),
			runner.WithLogger(l),
			runner.WithKubeFactory(cmdutil.NewFactory(matchVersionKubeConfigFlags)),
			runner.WithKubeNamespace(ns),
			runner.WithExecutable("", "--loglevel", l.GetLevel().String(), "run"),
			runner.WithSleep(sleep),
			runner.WithLoop(loop),
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
