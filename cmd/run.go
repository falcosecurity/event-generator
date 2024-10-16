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

package cmd

import (
	"fmt"
	"strings"
	"time"

	logger "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"

	"github.com/falcosecurity/event-generator/events"
	"github.com/falcosecurity/event-generator/pkg/runner"
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

	flags.Duration("sleep", time.Millisecond*100, "The length of time to wait before running an action. Non-zero values should contain a corresponding time unit (e.g. 1s, 2m, 3h). A value of zero means no sleep.")
	flags.Bool("loop", false, "Run in a loop")
	flags.Bool("all", false, "Run all actions, including those disabled by default")

	kubeConfigFlags := genericclioptions.NewConfigFlags(false)
	kubeConfigFlags.AddFlags(flags)
	matchVersionKubeConfigFlags := cmdutil.NewMatchVersionFlags(kubeConfigFlags)
	matchVersionKubeConfigFlags.AddFlags(flags)

	ns := flags.Lookup("namespace")
	ns.DefValue = DefaultNamespace
	if err := ns.Value.Set(DefaultNamespace); err != nil {
		panic(err)
	}

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

		all, err := flags.GetBool("all")
		if err != nil {
			return err
		}

		l := logger.StandardLogger()

		// Honor --all too!
		exeArgs := fmt.Sprintf("--loglevel %s run", l.GetLevel().String())
		if all {
			exeArgs += " --all"
		}

		runOpts := []runner.Option{
			runner.WithLogger(l),
			runner.WithKubeNamespace(ns),
			runner.WithKubeFactory(cmdutil.NewFactory(matchVersionKubeConfigFlags)),
			// todo(leogr): inherit other flags
			runner.WithExecutable("", strings.Split(exeArgs, " ")...),
			runner.WithSleep(sleep),
			runner.WithLoop(loop),
			runner.WithAllEnabled(all),
		}

		// allow to override runOpts by appending given options
		options = append(runOpts, options...)

		r, err := runner.New(options...)
		if err != nil {
			return err
		}

		c.SilenceUsage = true

		if len(args) == 0 {
			return r.Run(c.Context(), events.All())
		}

		evts, err := parseEventsArg(args[0])
		if err != nil {
			return err
		}

		return r.Run(c.Context(), evts)
	}
}
