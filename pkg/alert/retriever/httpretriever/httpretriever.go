// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The Falco Authors
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

package httpretriever

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"

	"github.com/falcosecurity/event-generator/pkg/alert"
)

// SecurityMode defines the security mode the HTTP retriever server should use.
type SecurityMode int

const (
	// SecurityModeInsecure specifies that the HTTP server must not use TLS.
	SecurityModeInsecure SecurityMode = iota
	// SecurityModeTLS specifies that the HTTP server must use TLS, but not verify client identity.
	SecurityModeTLS
	// SecurityModeMutualTLS specifies that the HTTP server must use TLS and verify client identity (mTLS).
	SecurityModeMutualTLS
)

// config stores the HTTP retriever underlying configuration.
type config struct {
	address      string
	securityMode SecurityMode
	certFile     string
	keyFile      string
	caRootFile   string
}

// Option for configuring the HTTP retriever.
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

// WithAddress allows to specify the address the HTTP server should be bound to.
func WithAddress(address string) Option {
	return newFuncOption(func(c *config) error {
		c.address = address
		return nil
	})
}

// WithSecurityMode allows to specify the security mode to be used (e.g.: SecurityModeMutualTLS enabling mutual TLS).
func WithSecurityMode(securityMode SecurityMode) Option {
	return newFuncOption(func(c *config) error {
		c.securityMode = securityMode
		return nil
	})
}

// WithCertFile allows to specify the path of the server certificate to be used for TLS against the Falco HTTP client.
func WithCertFile(certFile string) Option {
	return newFuncOption(func(c *config) error {
		c.certFile = certFile
		return nil
	})
}

// WithKeyFile allows to specify the path of the server private key to be used for TLS against the Falco HTTP client.
func WithKeyFile(keyFile string) Option {
	return newFuncOption(func(c *config) error {
		c.keyFile = keyFile
		return nil
	})
}

// WithCARootFile allows to specify the path of the CA root certificate used for Falco HTTP client's certificate
// validation.
func WithCARootFile(caRootFile string) Option {
	return newFuncOption(func(c *config) error {
		c.caRootFile = caRootFile
		return nil
	})
}

// httpRetriever implements an HTTP alert retriever.
type httpRetriever struct {
	logger logr.Logger
	config
}

// Verify that httpRetriever implements alert.Retriever interface.
var _ alert.Retriever = (*httpRetriever)(nil)

var defaultConfig = &config{
	address:      "localhost:8080",
	securityMode: SecurityModeInsecure,
	certFile:     "/etc/falco/certs/server.crt",
	keyFile:      "/etc/falco/certs/server.key",
	caRootFile:   "/etc/falco/certs/ca.crt",
}

// New creates a new HTTP alert retriever and configures it with the provided options.
func New(logger logr.Logger, options ...Option) (alert.Retriever, error) {
	r := &httpRetriever{
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

type rawAlert struct {
	Rule         string          `json:"rule"`
	Hostname     string          `json:"hostname"`
	Source       string          `json:"source"`
	Priority     string          `json:"priority"`
	OutputFields rawOutputFields `json:"output_fields"`
}

type rawOutputFields map[string]string

// UnmarshalJSON implements the json.Unmarshaler interface for rawOutputFields.
func (f *rawOutputFields) UnmarshalJSON(data []byte) error {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	*f = make(map[string]string)

	for k, v := range raw {
		if v != nil {
			(*f)[k] = fmt.Sprintf("%v", v)
		}
	}
	return nil
}

func parseAlert(reader io.Reader) (*alert.Alert, error) {
	var rawAlrt rawAlert
	if err := json.NewDecoder(reader).Decode(&rawAlrt); err != nil {
		return nil, fmt.Errorf("error parsing JSON: %w", err)
	}

	priority := alert.Priority(strings.ToLower(rawAlrt.Priority))
	return &alert.Alert{
		Priority:     priority,
		Rule:         rawAlrt.Rule,
		OutputFields: rawAlrt.OutputFields,
		Hostname:     rawAlrt.Hostname,
		Source:       rawAlrt.Source,
	}, nil
}

// setupServeMux sets up an http.ServeMux instance handling Falco alerts submitted via POST requests on "/". Falco
// alerts are parsed and sent over the provided channel.
func (r *httpRetriever) setupServeMux(ctx context.Context, alertCh chan<- *alert.Alert) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc(http.MethodPost+" /", func(w http.ResponseWriter, req *http.Request) {
		// Handle context cancellation early to avoid wasting time parsing the alert.
		if ctx.Err() != nil {
			return
		}

		alrt, err := parseAlert(req.Body)
		if err != nil {
			r.logger.Error(err, "Error decoding Falco alert", "suggestion", "enable Falco's json_output config")
			return
		}

		w.WriteHeader(http.StatusOK)

		logger := r.logger.WithValues("rule", alrt.Rule, "source", alrt.Source, "priority", alrt.Priority, "hostname",
			alrt.Hostname)
		logger.V(1).Info("Received alert")
		select {
		case <-ctx.Done():
			return
		case alertCh <- alrt:
			logger.V(1).Info("Sent alert downstream")
		}
	})
	return mux
}

func (r *httpRetriever) isTLSEnabled() bool {
	return r.securityMode == SecurityModeTLS || r.securityMode == SecurityModeMutualTLS
}

// Parse and return a TLS configuration based on the retriever configuration. If TLS is not requested, nil is returned.
func (r *httpRetriever) parseTLSConfig() (*tls.Config, error) {
	if !r.isTLSEnabled() {
		return nil, nil
	}

	serverCert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return nil, fmt.Errorf("error loading the server X.509 key pair: %w", err)
	}

	// Server-side TLS requested. No client verification needed.
	if r.securityMode == SecurityModeTLS {
		return &tls.Config{
			ClientAuth:   tls.NoClientCert,
			Certificates: []tls.Certificate{serverCert},
			MinVersion:   tls.VersionTLS12,
		}, nil
	}

	// Mutual TLS requested. Load client CA root certificate.
	clientRootCA, err := os.ReadFile(r.caRootFile)
	if err != nil {
		return nil, fmt.Errorf("error reading the client CA root file certificate: %w", err)
	}

	clientCertPool := x509.NewCertPool()
	if ok := clientCertPool.AppendCertsFromPEM(clientRootCA); !ok {
		return nil, fmt.Errorf("error appending the client root CA to the certificate pool")
	}

	return &tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    clientCertPool,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

func (r *httpRetriever) AlertStream(ctx context.Context) (<-chan *alert.Alert, error) {
	// Set up the HTTP server.
	alertCh := make(chan *alert.Alert)
	mux := r.setupServeMux(ctx, alertCh)

	tlsConfig, err := r.parseTLSConfig()
	if err != nil {
		return nil, fmt.Errorf("error parsing TLS config: %w", err)
	}

	server := &http.Server{
		Addr:         r.address,
		Handler:      mux,
		TLSConfig:    tlsConfig,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// The following goroutines orchestrate HTTP server spawning and shutdown, while ensuring that the returned channel
	// is only closed after this latter.
	wg := &sync.WaitGroup{}

	innerCtx, innerCtxCancel := context.WithCancel(ctx)

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-innerCtx.Done()
		shutdownCtx, shutdownCtxCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer shutdownCtxCancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			r.logger.Error(err, "Error shutting down the HTTP server gracefully. Will attempt to forcefully close it")
			if err := server.Close(); err != nil {
				r.logger.Error(err, "Error forcefully closing the HTTP server after attempting to shutting down it")
			} else {
				r.logger.V(1).Info("HTTP server forcefully closed")
			}
			return
		}
		r.logger.V(1).Info("HTTP server shutdown completed")
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer innerCtxCancel()
		var err error
		if r.isTLSEnabled() {
			err = server.ListenAndServeTLS("", "")
		} else {
			err = server.ListenAndServe()
		}
		if !errors.Is(err, http.ErrServerClosed) {
			r.logger.Error(err, "Failed to start listening and serving for HTTP server", "address", r.address)
		} else {
			r.logger.V(1).Info("HTTP server listening and serving stopped")
		}
	}()

	go func() {
		defer close(alertCh)
		wg.Wait()
	}()

	return alertCh, nil
}
