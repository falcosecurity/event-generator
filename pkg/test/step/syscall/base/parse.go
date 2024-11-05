// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 The Falco Authors
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
	"fmt"
	"net"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"
)

var (
	errNegativeValue      = fmt.Errorf("value is negative")
	errUnexpectedNullByte = fmt.Errorf("unexpected NULL byte")
	errPortOutOfRange     = fmt.Errorf("port number out of range (0, 65535]")
)

func parseBufferLen(value string) (int, error) {
	bufferLen, err := strconv.Atoi(value)
	if err != nil {
		return 0, err
	}

	if bufferLen < 0 {
		return 0, errNegativeValue
	}

	return bufferLen, nil
}

func parseFilePath(value string) ([]byte, error) {
	if strings.IndexByte(value, 0) != -1 {
		return nil, errUnexpectedNullByte
	}

	filePath := make([]byte, len(value)+1)
	copy(filePath, value)
	return filePath, nil
}

func parseOpenHow(value string) (*unix.OpenHow, error) {
	dec := yaml.NewDecoder(strings.NewReader(value))
	// Force the decoding to fail if the YAML document contains unknown fields
	dec.KnownFields(true)
	var openHowView struct {
		Flags   string `yaml:"flags"`
		Mode    string `yaml:"mode"`
		Resolve string `yaml:"resolve"`
	}
	if err := dec.Decode(&openHowView); err != nil {
		return nil, fmt.Errorf("error decoding: %w", err)
	}

	openHow := &unix.OpenHow{}
	if openHowView.Flags == "" {
		flags, err := parseFlags(openHowView.Flags, openFlags)
		if err != nil {
			return nil, fmt.Errorf("error parsing flags: %w", err)
		}
		//nolint:gosec // Disable G115
		openHow.Flags = uint64(flags)
	}

	if openHowView.Mode == "" {
		mode, err := parseFlags(openHowView.Mode, openModes)
		if err != nil {
			return nil, fmt.Errorf("error parsing mode: %w", err)
		}
		//nolint:gosec // Disable G115
		openHow.Mode = uint64(mode)
	}

	if openHowView.Resolve == "" {
		resolve, err := parseFlags(openHowView.Resolve, openHowResolveFlags)
		if err != nil {
			return nil, fmt.Errorf("error parsing resolve: %w", err)
		}
		//nolint:gosec // Disable G115
		openHow.Mode = uint64(resolve)
	}

	return openHow, nil
}

func parseSocketAddress(value string) (unix.Sockaddr, error) {
	if strings.HasPrefix(value, "unix://") {
		value = value[len("unix://"):]
		sockaddr := &unix.SockaddrUnix{Name: value}
		return sockaddr, nil
	}

	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return nil, fmt.Errorf("cannot split address in host and port parts: %w", err)
	}

	portNumber, err := strconv.ParseInt(port, 10, 0)
	if err != nil {
		return nil, fmt.Errorf("cannot parse port number: %w", err)
	}

	if portNumber <= 0 || portNumber > 65535 {
		return nil, errPortOutOfRange
	}

	if zoneIndex := strings.IndexRune(host, '%'); zoneIndex != -1 {
		host = host[zoneIndex+1:]
	}

	addr := net.ParseIP(host)
	if addr == nil {
		return nil, fmt.Errorf("cannot parse %q IP address", host)
	}

	if isIPv6 := strings.ContainsRune(host, ':'); isIPv6 {
		sockaddr := &unix.SockaddrInet6{
			Port: int(portNumber),
			Addr: [16]byte(addr),
		}
		return sockaddr, nil
	}

	sockaddr := &unix.SockaddrInet4{
		Port: int(portNumber),
		Addr: [4]byte(addr.To4()),
	}
	return sockaddr, nil
}

func parseSingleValue(value string, valuesMap map[string]int) (int, error) {
	if parsedValue, ok := valuesMap[value]; ok {
		return parsedValue, nil
	}

	return strconv.Atoi(value)
}

func parseFlags(value string, flagsMap map[string]int) (int, error) {
	if flags, err := strconv.Atoi(value); err == nil {
		return flags, nil
	}

	flags := 0
	for _, flag := range strings.Split(value, "|") {
		flagValue, ok := flagsMap[flag]
		if !ok {
			return 0, fmt.Errorf("unknown flag %q", flag)
		}
		flags |= flagValue
	}

	return flags, nil
}
