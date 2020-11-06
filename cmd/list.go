package cmd

import (
	"fmt"
	"regexp"
	"sort"

	// register event collections
	_ "github.com/falcosecurity/event-generator/events/k8saudit"
	_ "github.com/falcosecurity/event-generator/events/syscall"

	"github.com/falcosecurity/event-generator/events"
	"github.com/spf13/cobra"
)

// NewList instantiates the list subcommand.
func NewList() *cobra.Command {
	c := &cobra.Command{
		Use:   "list [regexp]",
		Short: "List available actions",
		Long: `Without arguments it lists all actions, otherwise only those actions matching the given regular expression.
`,
		Args:              cobra.MaximumNArgs(1),
		DisableAutoGenTag: true,
	}

	c.RunE = func(c *cobra.Command, args []string) error {

		var evts map[string]events.Action
		if len(args) == 0 {
			evts = events.All()
		} else {

			reg, err := regexp.Compile(args[0])
			if err != nil {
				return err
			}

			evts = events.ByRegexp(reg)
			if len(evts) == 0 {
				return fmt.Errorf(`no events matching '%s'`, args[0])
			}

		}

		actions := make([]string, len(evts))
		i := 0
		for action := range evts {
			actions[i] = action
			i++
		}
		sort.Strings(actions)

		for _, v := range actions {
			fmt.Println(v)
		}

		return nil
	}

	return c
}
