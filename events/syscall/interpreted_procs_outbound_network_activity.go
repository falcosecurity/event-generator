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
	InterpretedProcsOutboundNetworkActivity,
	events.WithDisabled(), // this rules is not included in falco_rules.yaml (stable rules), so disable the action
)

func InterpretedProcsOutboundNetworkActivity(h events.Helper) error {
	// Python script to perform outbound network activity
	pythonScript := `
import socket

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.connect(('127.0.0.1', 8000))

print("Connected to server on port 8000...")

data = b"Hello, server!"
server_socket.sendall(data)

server_socket.close()
`

	// Execute the Python script
	cmd := exec.Command("python3", "-c", pythonScript)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return err
	}

	// Log the output and event description
	h.Log().Infof("Interpreted program performed outgoing network connection")
	h.Log().Infof("Python script output:\n%s", output)

	return nil
}