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
	"os"
	"regexp"

	"github.com/falcosecurity/client-go/pkg/client"
	"github.com/falcosecurity/event-generator/events"
	"github.com/falcosecurity/event-generator/pkg/declarative"
	"github.com/spf13/pflag"
	"gopkg.in/yaml.v2"
)

// This function parses the yaml file given and returns the tests data int it
func parseYamlFile(filepath string) (declarative.Tests, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return declarative.Tests{}, fmt.Errorf("an error occurred while parsing file %s: %w", filepath, err)
	}
	var tests declarative.Tests
	err = yaml.Unmarshal(data, &tests)
	if err != nil {
		return declarative.Tests{}, fmt.Errorf("an error occurred while unmarshalling yaml data: %w", err)
	}
	return tests, nil
}

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
