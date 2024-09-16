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

package helper

import (
	"bytes"
	"errors"
	"net"
	"time"

	"github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(CombinedServerClient)

func CombinedServerClient(h events.Helper) error {
	serverAddr, err := net.ResolveUDPAddr("udp", "localhost:1234")
	if err != nil {
		return err
	}

	// start server
	serverConn, err := net.ListenUDP("udp", serverAddr)
	if err != nil {
		return err
	}
	defer func() {
		if err := serverConn.Close(); err != nil {
			h.Log().WithError(err).Error("failed to close server connection")
		}
	}()

	h.Log().Debug("server is listening on localhost:1234")

	buf := make([]byte, 1024)

	// wait for client to send data
	srvErr := make(chan error)
	go func() {
		defer close(srvErr)
		_, _, err = serverConn.ReadFromUDP(buf)
		srvErr <- err
	}()

	// connect to server and send data
	clientConn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		return err
	}
	defer func() {
		if err := clientConn.Close(); err != nil {
			h.Log().WithError(err).Error("failed to close client connection")
		}
	}()

	data := []byte{0xCA, 0xFE, 0xBA, 0xBE}
	if _, err = clientConn.Write(data); err != nil {
		return err
	}

	h.Log().Debugf("client sent: %X", data)

	// wait for server to respond or timeout
	select {
	case err := <-srvErr:
		if err != nil {
			return err
		}
		h.Log().Debugf("server received: %X", bytes.Trim(buf, "\x00"))
		return nil
	case <-time.After(5 * time.Second):
		return errors.New("timeout")
	}
}
