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
	"net"
	"time"

	"github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(CombinedServerClient)

func CombinedServerClient(h events.Helper) error {
	errCh := make(chan error)
	go func() {
		errCh <- runServer()
	}()

	time.Sleep(1 * time.Second)
	return runClient()
}

func runServer() error {
	serverAddr, err := net.ResolveUDPAddr("udp", ":80")
	if err != nil {
		return err
	}

	serverConn, err := net.ListenUDP("udp", serverAddr)
	if err != nil {
		return err
	}

	defer serverConn.Close()
	buf := make([]byte, 1024)
	_, _, err = serverConn.ReadFromUDP(buf)
	return err
}

func runClient() error {
	serverAddr, err := net.ResolveUDPAddr("udp", "localhost:80")
	if err != nil {
		return err
	}

	clientConn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		return err
	}
	defer clientConn.Close()

	data := []byte{0xCA, 0xFE, 0xBA, 0xBE}
	_, err = clientConn.Write(data)
	if err != nil {
		return err
	}
	return nil
}
