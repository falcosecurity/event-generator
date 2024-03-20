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

var _ = events.Register(InterpretedProcsInboundNetworkActivity)

func InterpretedProcsInboundNetworkActivity(h events.Helper) error {
    // Python script to perform inbound network activity
    pythonScript := `
import socket

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('0.0.0.0', 8000))
server_socket.listen(1)

print("Server is listening on port 8000")

client_socket, addr = server_socket.accept()
print(f"Received connection from {addr}")

data = client_socket.recv(1024)
print(f"Received data: {data.decode()}")

client_socket.close()
server_socket.close()
`

    cmd := exec.Command("python3", "-c", pythonScript)
    output, err := cmd.CombinedOutput()
    if err != nil {
        return err
    }

    h.Log().Infof("Interpreted program received/listened for network traffic")
    h.Log().Infof("Python script output:\n%s", output)

    return nil
}