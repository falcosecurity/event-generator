package cmd

import (
	"fmt"
	"regexp"

	"github.com/falcosecurity/client-go/pkg/client"
	"github.com/falcosecurity/event-generator/events"
	"github.com/spf13/pflag"
)

func parseEventsArg(arg string) (map[string]events.Action, error) {
	reg, err := regexp.Compile(arg)
	if err != nil {
		return nil, err
	}

	evts := events.ByRegexp(reg)
	if len(evts) == 0 {
		return nil, fmt.Errorf(`no events matching '%s'`, arg)
	}

	return evts, nil
}

func grpcFlags(flags *pflag.FlagSet) *client.Config {
	grpcCfg := &client.Config{}
	flags.StringVar(&grpcCfg.UnixSocketPath, "grpc-unix-socket", "unix:///run/falco/falco.sock", "Unix socket path for connecting to a Falco gRPC server")
	flags.StringVar(&grpcCfg.Hostname, "grpc-hostname", "localhost", "Hostname for connecting to a Falco gRPC server")
	flags.Uint16Var(&grpcCfg.Port, "grpc-port", 5060, "Port for connecting to a Falco gRPC server")
	flags.StringVar(&grpcCfg.CertFile, "grpc-cert", "/etc/falco/certs/client.crt", "Cert file path for connecting to a Falco gRPC server")
	flags.StringVar(&grpcCfg.KeyFile, "grpc-key", "/etc/falco/certs/client.key", "Key file path for connecting to a Falco gRPC server")
	flags.StringVar(&grpcCfg.CARootFile, "grpc-ca", "/etc/falco/certs/ca.crt", "CA root file path for connecting to a Falco gRPC server")
	return grpcCfg
}
