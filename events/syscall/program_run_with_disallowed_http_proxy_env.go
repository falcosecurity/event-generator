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
	"os"
	"os/exec"

	"github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(
	ProgramRunWithDisallowedHttpProxyEnv,
	// events.WithDisabled(), // this rules is not included in falco_rules.yaml (stable rules), so disable the action
)

func ProgramRunWithDisallowedHttpProxyEnv(h events.Helper) error {
	// Get the current value of HTTP_PROXY environment variable
	originalHTTPProxy := os.Getenv("HTTP_PROXY")

	// Modify HTTP_PROXY environment variable
	os.Setenv("HTTP_PROXY", "http://my.http.proxy.com ")

	// Ensure the original HTTP_PROXY value is reverted even if an error occurs
	defer os.Setenv("HTTP_PROXY", originalHTTPProxy)

	h.Log().Info("executing curl or wget with disallowed HTTP_PROXY environment variable")
	cmd := exec.Command("curl", "http://example.com")

	return cmd.Run()
}
