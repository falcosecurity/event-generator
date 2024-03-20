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

package helper

import (
	"net"
	"strconv"

	"github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(InboundConnection)

func InboundConnection(h events.Helper) error {
	address, _ := getAvailableLocalAddress()
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	defer listener.Close()
	return nil
}

func getAvailableLocalAddress() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		if ipNet.IP.IsLoopback() || ipNet.IP.IsUnspecified() {
			continue
		}
		ip := ipNet.IP.To4()
		if ip == nil {
			continue
		}
		listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: ip})
		if err != nil {
			continue
		}
		listener.Close()
		return ip.String() + ":" + strconv.Itoa(listener.Addr().(*net.TCPAddr).Port), nil
	}
	return "", err
}
