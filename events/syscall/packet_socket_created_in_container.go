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
    "encoding/binary"
    "syscall"

    "github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(CreatePacketSocket)

func CreatePacketSocket(h events.Helper) error {
    if h.InContainer() {
        fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(networkToHostEndian(syscall.ETH_P_ALL)))
        if err != nil {
            h.Log().WithError(err).Error("Failed to create packet socket")
            return err
        }
        defer syscall.Close(fd)

        h.Log().Info("Packet socket created successfully!")
        syscall.Close(fd)
    } 

    return nil
}

// Function to convert network byte order to host byte order
func networkToHostEndian(value uint16) uint16 {
    bytes := make([]byte, 2)
    binary.BigEndian.PutUint16(bytes, value)
    return binary.LittleEndian.Uint16(bytes)
}
