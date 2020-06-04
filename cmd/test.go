package cmd

import (

	// register event collections
	"github.com/falcosecurity/client-go/pkg/client"
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

	grpcCfg := &client.Config{}

	flags.StringVar(&grpcCfg.UnixSocketPath, "grpc-unix-socket", "unix:///var/run/falco.sock", "Unix socket path for connecting to a Falco gRPC server")
	flags.StringVar(&grpcCfg.Hostname, "grpc-hostname", "localhost", "hostname for connecting to a Falco gRPC server")
	flags.Uint16Var(&grpcCfg.Port, "grpc-port", 5060, "port for connecting to a Falco gRPC server")
	flags.StringVar(&grpcCfg.CertFile, "grpc-cert", "/etc/falco/certs/client.crt", "cert file path for connecting to a Falco gRPC server")
	flags.StringVar(&grpcCfg.KeyFile, "grpc-key", "/etc/falco/certs/client.key", "key file path for connecting to a Falco gRPC server")
	flags.StringVar(&grpcCfg.CARootFile, "grpc-ca", "/etc/falco/certs/ca.crt", "CA root file path for connecting to a Falco gRPC server")

	c.RunE = func(c *cobra.Command, args []string) error {
		t, err := tester.New(grpcCfg)
		if err != nil {
			return err
		}
		return runEWithOpts(c, args, runner.WithPlugin(t))
	}

	return c
}
