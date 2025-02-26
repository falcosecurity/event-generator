// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 The Falco Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/thediveo/enumflag"

	"github.com/falcosecurity/event-generator/pkg/container/builder"
)

const (
	// DescriptionFileFlagName is the name of the flag allowing to specify the pathnames of files containing the YAML
	// tests descriptions.
	DescriptionFileFlagName = "description-file"
	// DescriptionDirFlagName is the name of the flag allowing to specify the pathnames of directories containing the
	// YAML tests description files.
	DescriptionDirFlagName = "description-dir"
	// DescriptionFlagName is the name of the flag allowing to specify the YAML tests description.
	DescriptionFlagName = "description"
	// TestIDFlagName is the name of the flag allowing to specify the test identifier.
	TestIDFlagName = "test-id"
	// BaggageFlagName is the name of the flag allowing to specify the baggage.
	BaggageFlagName = "baggage"
	// TimeoutFlagName is the name of the flag allowing to specify the test timeout.
	TimeoutFlagName = "timeout"
)

// Config represents the configuration shared among declarative commands. Among other shared settings, it also stores
// the values of the shared flags.
type Config struct {
	EnvKeysPrefix     string
	DeclarativeEnvKey string
	// DescriptionFileEnvKey is the environment variable key corresponding to DescriptionFileFlagName.
	DescriptionFileEnvKey string
	// DescriptionDirEnvKey is the environment variable key corresponding to DescriptionDirFlagName.
	DescriptionDirEnvKey string
	// DescriptionEnvKey is the environment variable key corresponding to DescriptionFlagName.
	DescriptionEnvKey string
	// TestIDEnvKey is the environment variable key corresponding to TestIDFlagName.
	TestIDEnvKey string
	// BaggageEnvKey is the environment variable key corresponding to BaggageFlagName.
	BaggageEnvKey string
	// TimeoutEnvKey is the environment variable key corresponding to TimeoutFlagName.
	TimeoutEnvKey string

	// Flags
	//
	// TestsDescriptionFiles is the list of pathnames of files containing the YAML tests descriptions. If
	// TestsDescription is provided, this is empty.
	TestsDescriptionFiles []string
	// TestsDescriptionDirs is the list of pathnames of directories containing the YAML tests description files. If
	// TestsDescription is provided, this is empty.
	TestsDescriptionDirs []string
	// TestsDescription is the YAML tests description. If TestsDescriptionFiles or TestsDescriptionDirs are provided,
	// this is empty.
	TestsDescription string
	// TestID is the test identifier in the form [testIDIgnorePrefix]<testUID>. It is used to propagate the test UID to
	// child processes in the process chain. The following invariants hold:
	// - the root process has no test ID
	// - the processes in the process chain but the last have the test ID in the form testIDIgnorePrefix<testUID>
	// - the last process in the process chain has the test ID in the form <testUID>
	// TestsTimeout is the maximal duration of the tests. If running tests lasts more than TestsTimeout, the execution
	// of all pending tasks is canceled.
	TestsTimeout time.Duration
	// ContainerRuntimeUnixSocketURL is the unix socket URL of the local container runtime.
	ContainerRuntimeUnixSocketURL string
	// ContainerBaseImageName is the event-generator base image to generate new containers.
	ContainerBaseImageName string
	// ContainerImagePullPolicy is container image pull policy.
	ContainerImagePullPolicy builder.ImagePullPolicy
	//
	// Hidden flags
	//
	// A process having a test ID in the form <testUID> (i.e.: the leaf process) is the only one that is monitored.
	TestID string
	// Baggage is the string encoding a set of supported key-value pairs. It is used for logging purposes and to
	// potentially generate the child process/container baggages.
	Baggage string
}

var containerImagePullPolicies = map[builder.ImagePullPolicy][]string{
	builder.ImagePullPolicyAlways:       {"always"},
	builder.ImagePullPolicyNever:        {"never"},
	builder.ImagePullPolicyIfNotPresent: {"ifnotpresent"},
}

// New creates a new config.
func New(declarativeEnvKey, envKeysPrefix string) *Config {
	commonConf := &Config{
		DeclarativeEnvKey:     declarativeEnvKey,
		EnvKeysPrefix:         envKeysPrefix,
		DescriptionFileEnvKey: envKeyFromFlagName(envKeysPrefix, DescriptionFileFlagName),
		DescriptionDirEnvKey:  envKeyFromFlagName(envKeysPrefix, DescriptionDirFlagName),
		DescriptionEnvKey:     envKeyFromFlagName(envKeysPrefix, DescriptionFlagName),
		TestIDEnvKey:          envKeyFromFlagName(envKeysPrefix, TestIDFlagName),
		BaggageEnvKey:         envKeyFromFlagName(envKeysPrefix, BaggageFlagName),
		TimeoutEnvKey:         envKeyFromFlagName(envKeysPrefix, TimeoutFlagName),
	}
	return commonConf
}

// InitCommandFlags initializes the provided command's flags and uses the config instance to store the flag bound
// values.
func (c *Config) InitCommandFlags(cmd *cobra.Command) {
	flags := cmd.Flags()

	// Miscellaneous flags.
	flags.StringSliceVarP(&c.TestsDescriptionFiles, DescriptionFileFlagName, "f", nil,
		"The pathnames of tests description YAML files specifying the tests to be run. Multiple pathnames can be "+
			"specified as a comma-separated list. The flag can be specified multiple times. Pathnames are evaluated "+
			"in order of appearance")
	flags.StringSliceVarP(&c.TestsDescriptionDirs, DescriptionDirFlagName, "d", nil,
		"The pathnames of directories containing tests description YAML files specifying the tests to be run. "+
			"Sub-directories of the provided pathnames are not recursively loaded. Only files with YAML extensions "+
			"are loaded. Multiple pathnames can be specified as a comma-separated list. The flag can be specified "+
			"multiple times. Pathnames are evaluated in order of appearance")
	flags.StringVar(&c.TestsDescription, DescriptionFlagName, "",
		"The YAML-formatted tests description string specifying the tests to be run")
	cmd.MarkFlagsMutuallyExclusive(DescriptionFileFlagName, DescriptionFlagName)
	cmd.MarkFlagsMutuallyExclusive(DescriptionDirFlagName, DescriptionFlagName)
	flags.DurationVarP(&c.TestsTimeout, TimeoutFlagName, "t", time.Minute,
		"The maximal duration of the tests. If running tests lasts more than the provided timeout, the execution of "+
			"all pending tasks is canceled")

	// Container runtime flags.
	flags.StringVar(&c.ContainerRuntimeUnixSocketURL, "container-runtime-unix-socket",
		"unix:///run/docker.sock", "The unix socket path of the local container runtime")
	flags.StringVar(&c.ContainerBaseImageName, "container-base-image",
		"docker.io/falcosecurity/event-generator:latest", "The event-generator base image to generate new containers")
	flags.Var(enumflag.New(&c.ContainerImagePullPolicy, "container-image-pull-policy", containerImagePullPolicies,
		enumflag.EnumCaseInsensitive), "container-image-pull-policy",
		"The container image pull policy; can be 'always', 'never' or 'ifnotpresent'")

	// Hidden flags.
	flags.StringVar(&c.TestID, TestIDFlagName, "",
		"(used during process chain building) The test identifier in the form <ignorePrefix><testUID>. It is used to "+
			"propagate the test UID to child processes/container in the process chain")
	flags.StringVar(&c.Baggage, BaggageFlagName, "",
		"(used during process chain building) The string encoding a set of supported key-value pais. It is used for "+
			"logging purposes and to potentially generate the child process/container baggage")
	_ = flags.MarkHidden(TestIDFlagName)
	_ = flags.MarkHidden(BaggageFlagName)
}

// envKeyFromFlagName converts the provided flag name into the corresponding environment variable key.
func envKeyFromFlagName(envKeysPrefix, flagName string) string {
	s := fmt.Sprintf("%s_%s", envKeysPrefix, strings.ToUpper(flagName))
	s = strings.ToUpper(s)
	return strings.ReplaceAll(s, "-", "_")
}
