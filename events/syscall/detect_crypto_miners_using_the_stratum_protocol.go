// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.
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

package syscall

import (
	"os/exec"

	"github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(
	DetectCryptoMinersUsingTheStratumProtocol,
	events.WithDisabled(), // this rules is not included in falco_rules.yaml (stable rules), so disable the action
)

func DetectCryptoMinersUsingTheStratumProtocol(h events.Helper) error {
	// NOTE: Crypto mining commands typically may resemble the following format,
	// where 'minersoftware' is an executable:
	// minersoftware -o stratum+tcp://example.com:3333 -u username -p password
	// However, for testing purposes, we're using 'ls' as a placeholder.
	cmd := exec.Command("ls", "-o stratum+tcp", "-u user", "-p pass")
	cmd.Run()
	return nil
}
