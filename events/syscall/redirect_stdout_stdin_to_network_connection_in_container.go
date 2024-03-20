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
	"net"

	"github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(RedirectStdoutStdinFromContainer)

var (
	remoteAddr string = "localhost:8080"
)

func RedirectStdoutStdinFromContainer(h events.Helper) error {
	if h.InContainer() {
		listener, _ := net.Listen("tcp", remoteAddr)
		defer listener.Close()
		// Accept incoming connections in a separate goroutine
		connChan := make(chan net.Conn)
		go func() {
			conn, _ := listener.Accept()
			connChan <- conn
		}()

		// Create a client connection
		clientConn, _ := net.Dial("tcp", remoteAddr)
		defer clientConn.Close()

		// Wait for the server connection
		serverConn := <-connChan

		// Redirect stdout to the network connection
		redirectStdout(serverConn)
	}
	return &events.ErrSkipped{
		Reason: "'Redirect Stdout/Stdin From Container' is applicable only to containers.",
	}
}