//go:build linux
// +build linux

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
	"syscall"

	"github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(PacketSocketCreatedInContainer)

func PacketSocketCreatedInContainer(h events.Helper) error {
	if h.InContainer() {
		fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(syscall.ETH_P_ALL))
		if err != nil {
			return err
		}
		defer syscall.Close(fd)
		syscall.Close(fd)
	}
	return &events.ErrSkipped{
		Reason: "'Packet Socket Created In Container' is applicable only to containers.",
	}
}
