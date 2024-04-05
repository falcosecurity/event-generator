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
	"fmt"
	"github.com/falcosecurity/event-generator/events"
	"net"
)

var _ = events.Register(
	UnexpectedK8sNodePortConnection,
	events.WithDisabled(), // this rule is not included in falco_rules.yaml (stable rules), so disable the action
)

func UnexpectedK8sNodePortConnection(h events.Helper) error {
	if h.InContainer() {
		port := 31000

		// Get the IP address of the "eth0" interface
		hostIP, err := getHostEth0IP()
		if err != nil {
			return err
		}

		addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", hostIP, port))
		if err != nil {
			return err
		}

		// Establish a UDP connection to the address

		conn, err := net.DialUDP("udp", nil, addr)
		if err != nil {
			return err
		}
		defer conn.Close() // Close the connection when the function returns
	}
	return &events.ErrSkipped{
		Reason: "'Unexpected k8s Nodeport connection' is applicable only to containers.",
	}
}
