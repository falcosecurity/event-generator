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
	"os"
	"os/signal"
	"strings"
	"syscall"

	// register event collections
	_ "github.com/falcosecurity/event-generator/events/k8saudit"
	_ "github.com/falcosecurity/event-generator/events/syscall"

	// Initialize all k8s client auth plugins
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	homedir "github.com/mitchellh/go-homedir"
	logger "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func init() {
	logger.SetFormatter(&logger.TextFormatter{
		ForceColors:            true,
		DisableLevelTruncation: false,
		DisableTimestamp:       true,
	})
}

// New instantiates the root command.
func New(configOptions *ConfigOptions) *cobra.Command {
	if configOptions == nil {
		configOptions = NewConfigOptions()
	}
	rootCmd := &cobra.Command{
		Use:               "event-generator",
		Short:             "A command line tool to perform a variety of suspect actions.",
		DisableAutoGenTag: true,
		PersistentPreRun: func(c *cobra.Command, args []string) {
			// PersistentPreRun runs before flags validation but after args validation.
			// Do not assume initialization completed during args validation.

			// at this stage configOptions is bound to command line flags only
			validateConfig(*configOptions)
			initLogger(configOptions.LogLevel, configOptions.LogFormat)
			logger.Debug("running with args: ", strings.Join(os.Args, " "))
			initConfig(configOptions.ConfigFile)

			// then bind all flags to ENV and config file
			flags := c.Flags()
			initEnv()
			initFlags(flags, map[string]bool{
				// exclude flags to be not bound to ENV and config file
				"config":    true,
				"loglevel":  true,
				"logformat": true,
				"help":      true,
			})
			// validateConfig(*configOptions) // enable if other flags were bound to configOptions
			debugFlags(flags)
		},
		Run: func(c *cobra.Command, args []string) {
			c.Help()
		},
	}

	// Global flags
	flags := rootCmd.PersistentFlags()
	flags.StringVarP(&configOptions.ConfigFile, "config", "c", configOptions.ConfigFile, "Config file path (default $HOME/.falco-event-generator.yaml if exists)")
	flags.StringVarP(&configOptions.LogLevel, "loglevel", "l", configOptions.LogLevel, "Log level")
	flags.StringVar(&configOptions.LogFormat, "logformat", configOptions.LogFormat, `available formats: "text" or "json"`)

	// Commands
	rootCmd.AddCommand(NewRun())
	rootCmd.AddCommand(NewBench())
	rootCmd.AddCommand(NewTest())
	rootCmd.AddCommand(NewList())

	return rootCmd
}

// Execute creates the root command and runs it.
func Execute() {
	ctx := WithSignals(context.Background())
	if err := New(nil).ExecuteContext(ctx); err != nil {
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
	viper.SetEnvPrefix("falco_event_generator")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
}

// initLogger configures the logger
func initLogger(logLevel string, logFormat string) {
	switch logFormat {
	case "text":
		// do nothing, default option
	case "json":
		logger.SetFormatter(&logger.JSONFormatter{
			DisableTimestamp: true,
		})
	default:
		logger.Fatalf(`"%s" log format is not supported`, logFormat)
	}
	lvl, err := logger.ParseLevel(logLevel)
	if err != nil {
		logger.Fatal(err)
	}
	logger.SetLevel(lvl)
}

// initConfig reads in config file, if any
func initConfig(configFile string) {
	if configFile != "" {
		viper.SetConfigFile(configFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			logger.WithError(err).Fatal("error getting the home directory")
		}

		viper.AddConfigPath(home)
		viper.SetConfigName(".falco-event-generator")
	}

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		logger.WithField("file", viper.ConfigFileUsed()).Info("using config file")
	} else {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found, ignore ...
			logger.Debug("running without a configuration file")
		} else {
			// Config file was found but another error was produced
			logger.WithField("file", viper.ConfigFileUsed()).WithError(err).Fatal("error running with config file")
		}
	}
}

// initFlags binds a full flag set to the configuration, using each flag's long name as the config key.
//
// Assuming viper's `AutomaticEnv` is enabled, when a flag is not present in the command line
// will fallback to one of (in order of precedence):
// - ENV (with FALCO_EVENT_GENERATOR prefix)
// - config file (e.g. ~/.falco-event-generator.yaml)
// - its default
func initFlags(flags *pflag.FlagSet, exclude map[string]bool) {
	viper.BindPFlags(flags)
	flags.VisitAll(func(f *pflag.Flag) {
		if exclude[f.Name] {
			return
		}
		viper.SetDefault(f.Name, f.DefValue)
		if v := viper.GetString(f.Name); v != f.DefValue {
			flags.Set(f.Name, v)
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
