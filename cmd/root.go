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
	"context"
	"errors"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/go-logr/logr"
	homedir "github.com/mitchellh/go-homedir"
	logger "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	// Initialize all k8s client auth plugins.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"github.com/falcosecurity/event-generator/cmd/declarative"
	// register event collections.
	_ "github.com/falcosecurity/event-generator/events/k8saudit"
	_ "github.com/falcosecurity/event-generator/events/syscall"
	"github.com/falcosecurity/event-generator/pkg/log"
)

func init() {
	logger.SetFormatter(&logger.TextFormatter{
		ForceColors:            true,
		DisableLevelTruncation: false,
		DisableTimestamp:       true,
	})
}

const (
	// envKeysPrefix is used as environment variable prefix configuration for viper.
	envKeysPrefix = "falco_event_generator"
	// declarativeEnvKey is used to distinguish between command-line invocation of the "declarative run" subcommand and
	// the subcommand invoking itself during process chain creation.
	declarativeEnvKey = "DECLARATIVE"
)

// New instantiates the root command.
func New(configOptions *ConfigOptions) *cobra.Command {
	if configOptions == nil {
		configOptions = NewConfigOptions()
	}
	rootCmd := &cobra.Command{
		Use:               "event-generator",
		Short:             "A command line tool to perform a variety of suspect actions.",
		DisableAutoGenTag: true,
		TraverseChildren:  true,
		PersistentPreRun: func(c *cobra.Command, args []string) {
			// PersistentPreRun runs before flags validation but after args validation.
			// Do not assume initialization completed during args validation.

			// At this stage configOptions is bound to command line flags only. Use only config file flag to
			// initialize the remaining configuration.
			validateConfig(*configOptions)
			initConfig(configOptions.ConfigFile)

			// then bind all flags to ENV and config file
			flags := c.Flags()
			initEnv()
			excludedFlags := map[string]struct{}{"config": {}}
			initFlags(flags, excludedFlags)

			initLoggers(configOptions.LogLevel, configOptions.LogFormat)
			logger.Debug("running with args: ", strings.Join(os.Args, " "))
			validateConfig(*configOptions)
			debugFlags(flags)

			// Inject logr logger into context.
			ctx := logr.NewContext(c.Context(), log.Logger)
			c.SetContext(ctx)
		},
		Run: func(c *cobra.Command, args []string) {
			if err := c.Help(); err != nil {
				logger.WithError(err).Fatal("error running help")
			}
		},
	}

	// Global flags
	flags := rootCmd.PersistentFlags()
	flags.StringVarP(&configOptions.ConfigFile, "config", "c", configOptions.ConfigFile,
		"Config file path (default $HOME/.falco-event-generator.yaml if exists)")
	flags.StringVarP(&configOptions.LogLevel, "loglevel", "l", configOptions.LogLevel, "Log level")
	flags.StringVar(&configOptions.LogFormat, "logformat", configOptions.LogFormat,
		`available formats: "text" or "json"`)

	// Commands
	rootCmd.AddCommand(NewRun())
	rootCmd.AddCommand(NewBench())
	rootCmd.AddCommand(NewTest())
	rootCmd.AddCommand(NewList())
	rootCmd.AddCommand(declarative.New(declarativeEnvKey, envKeysPrefix))

	return rootCmd
}

// Execute creates the root command and runs it.
func Execute() {
	ctx := WithSignals(context.Background())
	rootCmd := New(nil)
	// declarativeEnvKey is not mapped on viper and cobra on purpose.
	if v := os.Getenv(declarativeEnvKey); v != "" {
		rootCmd.SetArgs([]string{"declarative", "run"})
	}

	if err := rootCmd.ExecuteContext(ctx); err != nil {
		logger.WithError(err).Fatal("error executing event-generator")
	}
}

// WithSignals returns a copy of ctx with a new Done channel.
// The returned context's Done channel is closed when a SIGKILL or SIGTERM signal is received.
func WithSignals(ctx context.Context) context.Context {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(ctx)
	go func() {
		defer cancel()
		select {
		case <-ctx.Done():
			return
		case s := <-sigCh:
			switch s {
			case os.Interrupt:
				logger.Infof("received SIGINT, shutting down")
			case syscall.SIGTERM:
				logger.Infof("received SIGTERM, shutting down")
			}
			return
		}
	}()
	return ctx
}

// validateConfig
func validateConfig(configOptions ConfigOptions) {
	if errs := configOptions.Validate(); errs != nil {
		for _, err := range errs {
			logger.WithError(err).Error("error validating config options")
		}
		logger.Fatal("exiting for validation errors")
	}
}

// initEnv enables automatic ENV variables lookup
func initEnv() {
	viper.AutomaticEnv()
	viper.SetEnvPrefix(envKeysPrefix)
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
}

// initLoggers configures the logrus and the logr loggers.
// TODO: let the two loggers coexists until we decide to completely replace logrus with logr.
func initLoggers(logLevel, logFormat string) {
	logProfile := log.ProfileDevelopment
	switch logFormat {
	case "text":
		// do nothing, default option
	case "json":
		logger.SetFormatter(&logger.JSONFormatter{
			DisableTimestamp: true,
		})
		logProfile = log.ProfileProduction
	default:
		logger.Fatalf(`"%s" log format is not supported`, logFormat)
	}
	lvl, err := logger.ParseLevel(logLevel)
	if err != nil {
		logger.Fatal(err)
	}
	logger.SetLevel(lvl)

	if err := log.InitLogger(logProfile); err != nil {
		log.DefaultLogger.Error(err, "Error initializing logger")
		os.Exit(1)
	}
}

// initConfig reads in config file, if any
func initConfig(configFile string) {
	if configFile != "" {
		viper.SetConfigFile(configFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			log.DefaultLogger.Error(err, "Error getting the home directory")
			os.Exit(1)
		}

		viper.AddConfigPath(home)
		viper.SetConfigName(".falco-event-generator")
	}

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err != nil {
		var configFileNotFoundError viper.ConfigFileNotFoundError
		if errors.As(err, &configFileNotFoundError) {
			// Config file not found, ignore it.
			log.DefaultLogger.V(1).Info("Config file not found. Proceeding without it")
			return
		}

		log.DefaultLogger.Error(err, "Error loading config file", "file", viper.ConfigFileUsed())
		os.Exit(1)
	}

	log.DefaultLogger.Info("Configured config file", "file", viper.ConfigFileUsed())
}

// initFlags binds a full flag set to the configuration, using each flag's long name as the config key.
//
// Assuming viper's `AutomaticEnv` is enabled, when a flag is not present in the command line
// will fallback to one of (in order of precedence):
// - ENV (with FALCO_EVENT_GENERATOR prefix)
// - config file (e.g. ~/.falco-event-generator.yaml)
// - its default
func initFlags(flags *pflag.FlagSet, excludeSet map[string]struct{}) {
	if err := viper.BindPFlags(flags); err != nil {
		logger.WithError(err).Fatal("error binding flags to configuration")
	}

	flags.VisitAll(func(f *pflag.Flag) {
		if _, exclude := excludeSet[f.Name]; exclude {
			return
		}
		viper.SetDefault(f.Name, f.DefValue)
		if v := viper.GetString(f.Name); v != f.DefValue {
			if err := flags.Set(f.Name, v); err != nil {
				logger.WithError(err).WithField("flag", f.Name).Fatal("error setting flag")
			}
		}
	})
}

func debugFlags(flags *pflag.FlagSet) {
	fields := logger.Fields{}
	flags.VisitAll(func(f *pflag.Flag) {
		if f.Changed {
			fields[f.Name] = f.Value
		}
	})
	logger.WithFields(fields).Debug("running with options")
}
