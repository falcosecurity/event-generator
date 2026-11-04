// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The Falco Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package base

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestParseSocketAddress(t *testing.T) {
	loopback, err := net.InterfaceByName("lo")
	require.NoError(t, err)
	loopbackIndex := uint32(loopback.Index) //nolint:gosec // Disable G115

	ipv6Loopback := [16]byte{15: 1}
	linkLocal := [16]byte{0: 0xfe, 1: 0x80, 15: 1}
	tests := map[string]struct {
		value    string
		expected unix.Sockaddr
	}{
		"unix": {
			value:    "unix:///tmp/socket1.sock",
			expected: &unix.SockaddrUnix{Name: "/tmp/socket1.sock"},
		},
		"ipv4": {
			value:    "127.0.0.1:80",
			expected: &unix.SockaddrInet4{Port: 80, Addr: [4]byte{127, 0, 0, 1}},
		},
		"ipv6": {
			value:    "[::1]:80",
			expected: &unix.SockaddrInet6{Port: 80, Addr: ipv6Loopback},
		},
		"ipv6 with numeric zone": {
			value:    "[fe80::1%3]:80",
			expected: &unix.SockaddrInet6{Port: 80, ZoneId: 3, Addr: linkLocal},
		},
		"ipv6 with interface name zone": {
			value:    "[fe80::1%lo]:80",
			expected: &unix.SockaddrInet6{Port: 80, ZoneId: loopbackIndex, Addr: linkLocal},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			sockaddr, err := parseSocketAddress(tc.value)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, sockaddr)
		})
	}
}

func TestParseSocketAddressUnknownZone(t *testing.T) {
	_, err := parseSocketAddress("[fe80::1%nonexistent0]:80")
	assert.ErrorContains(t, err, `cannot parse "nonexistent0" zone`)
}
