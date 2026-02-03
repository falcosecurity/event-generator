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

package alertretriever

import (
	"fmt"

	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
	"github.com/thediveo/enumflag"

	"github.com/falcosecurity/event-generator/pkg/alert"
	"github.com/falcosecurity/event-generator/pkg/alert/retriever/httpretriever"
)

// securityMode defines the types of security mode used by the HTTP alert retriever.
type securityMode int

const (
	// securityModeInsecure specifies that the HTTP alert retriever shouldn't use any form of security.
	securityModeInsecure securityMode = iota
	// securityModeTLS specifies that the HTTP alert retriever should use TLS.
	securityModeTLS
	// securityModeMutualTLS specifies that the HTTP alert retriever should use mTLS.
	securityModeMutualTLS
)

var securityModes = map[securityMode][]string{
	securityModeInsecure:  {"insecure"},
	securityModeTLS:       {"tls"},
	securityModeMutualTLS: {"mtls"},
}

// Config holds the HTTP alert retriever configuration and builds an alert.Retriever from it.
type Config struct {
	address      string
	securityMode securityMode
	certFile     string
	keyFile      string
	caRootFile   string
}

// InitCommandFlags initializes the provided command's flags and uses the config instance to store the flag bound
// values.
func (c *Config) InitCommandFlags(cmd *cobra.Command) {
	flags := cmd.Flags()
	flags.StringVar(&c.address, "http-server-address", "localhost:8080",
		"The address the alert retriever HTTP server must be bound to")
	flags.Var(
		enumflag.New(&c.securityMode, "http-server-security-mode", securityModes, enumflag.EnumCaseInsensitive),
		"http-server-security-mode",
		"The security mode the alert retriever HTTP server must use; can be 'insecure', 'tls' or 'mtls'")
	flags.StringVar(&c.certFile, "http-server-cert", "/etc/falco/certs/server.crt",
		"the path of the server certificate to be used for TLS against the Falco HTTP client (to be used together with"+
			"--http-server-security-mode=(tls|mtls))")
	flags.StringVar(&c.keyFile, "http-server-key", "/etc/falco/certs/server.key",
		"The path of the server private key to be used for TLS against the Falco HTTP client (to be used together with"+
			"--http-server-security-mode=(tls|mtls))")
	flags.StringVar(&c.caRootFile, "http-client-ca", "/etc/falco/certs/ca.crt",
		"The path of the CA root certificate used for Falco HTTP client's certificate validation (to be used together "+
			"with --http-server-security-mode=mtls)")
}

// Build builds an alert.Retriever from the current configuration.
func (c *Config) Build(logger logr.Logger) (alert.Retriever, error) {
	securityMode := decodeSecurityMode(c.securityMode)
	httpRetrieverOptions := []httpretriever.Option{
		httpretriever.WithAddress(c.address),
		httpretriever.WithSecurityMode(securityMode),
		httpretriever.WithCertFile(c.certFile),
		httpretriever.WithKeyFile(c.keyFile),
		httpretriever.WithCARootFile(c.caRootFile),
	}
	return httpretriever.New(logger.WithName("alert-retriever"), httpRetrieverOptions...)
}

// decodeSecurityMode decodes the provided security mode into something suitable for the HTTP retriever.
func decodeSecurityMode(securityMode securityMode) httpretriever.SecurityMode {
	switch securityMode {
	case securityModeInsecure:
		return httpretriever.SecurityModeInsecure
	case securityModeTLS:
		return httpretriever.SecurityModeTLS
	case securityModeMutualTLS:
		return httpretriever.SecurityModeMutualTLS
	default:
		panic(fmt.Sprintf("unsupported security mode %v", securityMode))
	}
}
