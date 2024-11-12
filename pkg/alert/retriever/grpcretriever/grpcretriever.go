// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 The Falco Authors
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

package grpcretriever

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	outputspb "github.com/falcosecurity/client-go/pkg/api/outputs"
	schemapb "github.com/falcosecurity/client-go/pkg/api/schema"
	"github.com/falcosecurity/client-go/pkg/client"
	"github.com/go-logr/logr"

	"github.com/falcosecurity/event-generator/pkg/alert"
)

// config stores the gRPC retriever underlying configuration.
type config struct {
	unixSocketPath string
	hostname       string
	port           uint16
	certFile       string
	keyFile        string
	caRootFile     string
	pollingTimeout time.Duration
}

// Option for configuring the gRPC retriever.
type Option interface {
	apply(*config) error
}

// funcOption is an implementation of Option storing a function that implements the requested apply method behavior.
type funcOption struct {
	f func(*config) error
}

func (cfo *funcOption) apply(c *config) error {
	return cfo.f(c)
}

// newFuncOption is a helper function to create a new funcOption from a function.
func newFuncOption(f func(*config) error) *funcOption {
	return &funcOption{f: f}
}

// WithUnixSocketPath allows to specify the unix socket path of the local Falco gRPC server (use only if you want to
// connect to Falco through a unix socket).
func WithUnixSocketPath(unixSocketPath string) Option {
	return newFuncOption(func(c *config) error {
		c.unixSocketPath = unixSocketPath
		return nil
	})
}

// WithHostname allows to specify the Falco gRPC server hostname.
func WithHostname(hostname string) Option {
	return newFuncOption(func(c *config) error {
		c.hostname = hostname
		return nil
	})
}

// WithPort allows to specify the Falco gRPC server port.
func WithPort(port uint16) Option {
	return newFuncOption(func(c *config) error {
		c.port = port
		return nil
	})
}

// WithCertFile allows to specify the path of the client certificate to be used for mutual TLS against the Falco gRPC
// server.
func WithCertFile(certFile string) Option {
	return newFuncOption(func(c *config) error {
		c.certFile = certFile
		return nil
	})
}

// WithKeyFile allows to specify the path of the client private key to be used for mutual TLS against the Falco gRPC
// server.
func WithKeyFile(keyFile string) Option {
	return newFuncOption(func(c *config) error {
		c.keyFile = keyFile
		return nil
	})
}

// WithCARootFile allows to specify the path of the CA root certificate used for Falco gRPC server's certificate
// validation.
func WithCARootFile(caRootFile string) Option {
	return newFuncOption(func(c *config) error {
		c.caRootFile = caRootFile
		return nil
	})
}

// WithPollingTimeout allows to specify the frequency of the watch operation on the gRPC Falco Outputs API stream.
func WithPollingTimeout(pollingTimeout time.Duration) Option {
	return newFuncOption(func(c *config) error {
		c.pollingTimeout = pollingTimeout
		return nil
	})
}

// gRPCRetriever implements a gRPC alert retriever.
type gRPCRetriever struct {
	logger logr.Logger
	config
}

// Verify that gRPCRetriever implements alert.Retriever interface.
var _ alert.Retriever = (*gRPCRetriever)(nil)

var defaultConfig = &config{
	unixSocketPath: "",
	hostname:       "localhost",
	port:           5060,
	certFile:       "/etc/falco/certs/client.crt",
	keyFile:        "/etc/falco/certs/client.key",
	caRootFile:     "/etc/falco/certs/ca.crt",
	pollingTimeout: 100 * time.Millisecond,
}

// New creates a new gRPC alert retriever and configures it with the provided options.
func New(logger logr.Logger, options ...Option) (alert.Retriever, error) {
	r := &gRPCRetriever{
		logger: logger,
		config: *defaultConfig,
	}

	for _, opt := range options {
		if err := opt.apply(&r.config); err != nil {
			return nil, fmt.Errorf("error applying option: %w", err)
		}
	}

	return r, nil
}

func (r *gRPCRetriever) AlertStream(ctx context.Context) (<-chan *alert.Alert, error) {
	conf := client.Config{
		Hostname:       r.hostname,
		Port:           r.port,
		CertFile:       r.certFile,
		KeyFile:        r.keyFile,
		CARootFile:     r.caRootFile,
		UnixSocketPath: r.unixSocketPath,
	}
	falcoClient, err := client.NewForConfig(ctx, &conf)
	if err != nil {
		return nil, fmt.Errorf("error creating new Falco client: %w", err)
	}

	outputs, err := falcoClient.Outputs()
	if err != nil {
		return nil, fmt.Errorf("error getting client for Falco Outputs API: %w", err)
	}

	stream, err := outputs.Sub(ctx)
	if err != nil {
		return nil, fmt.Errorf("error subscribing to Falco Outputs API stream: %w", err)
	}

	return r.alertStream(ctx, stream), nil
}

// alertStream returns a channel that can be used to consume a stream of Falco alerts. The returned channel is closed if
// the provided context is canceled.
func (r *gRPCRetriever) alertStream(ctx context.Context, stream outputspb.Service_SubClient) <-chan *alert.Alert {
	alertCh := make(chan *alert.Alert)
	go func() {
		defer close(alertCh)
		if err := client.OutputsWatch(ctx, stream, func(res *outputspb.Response) error {
			logger := r.logger.WithValues("rule", res.Rule, "source", res.Source, "priority", res.Priority, "hostname",
				res.Hostname)
			logger.V(1).Info("Received alert")
			priority := res.Priority
			priorityName, ok := schemapb.Priority_name[int32(priority)]
			if !ok {
				logger.Info("Received alert with unknown priority", "priority", priority)
				return nil
			}

			alrt := &alert.Alert{
				Priority:     alert.Priority(strings.ToLower(priorityName)),
				Rule:         res.Rule,
				OutputFields: res.OutputFields,
				Hostname:     res.Hostname,
				Source:       res.Source,
			}

			select {
			case <-ctx.Done():
			case alertCh <- alrt:
				logger.V(1).Info("Sent alert downstream")
			}

			return nil
		}, r.pollingTimeout); err != nil && !errors.Is(err, ctx.Err()) {
			r.logger.Error(err, "Error getting alert from Falco Outputs API stream")
		} else {
			r.logger.V(1).Info("Read from Falco Outputs API stream stopped")
		}
	}()

	return alertCh
}
