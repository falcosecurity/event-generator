// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 The Falco Authors
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
	"reflect"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

var (
	errMustBePositive       = fmt.Errorf("value must be positive")
	errMustBeString         = fmt.Errorf("value must be a string")
	errCannotConvertToInt   = fmt.Errorf("cannot convert to int")
	errUnexpectedNullByte   = fmt.Errorf("unexpected NULL byte")
	errPortOutOfRange       = fmt.Errorf("port number out of range (0, 65535]")
	errMustBeStringOrUint64 = fmt.Errorf("value must be a string or an uint64")
	errMustBeMap            = fmt.Errorf("value must be a map")
)

func parseInt64(value any) (int64, error) {
	v := reflect.ValueOf(value)
	var n int64
	typ := reflect.TypeOf(n)
	if !v.CanConvert(typ) {
		return 0, errCannotConvertToInt
	}

	return v.Convert(typ).Int(), nil
}

func parseString(value any) (string, error) {
	v, ok := value.(string)
	if !ok {
		return "", errMustBeString
	}

	return v, nil
}

func parseBufferLen(value any) (int64, error) {
	bufferLen, err := parseInt64(value)
	if err != nil {
		return 0, err
	}

	if bufferLen < 0 {
		return 0, errMustBePositive
	}

	return bufferLen, nil
}

func parseFilePath(value any) ([]byte, error) {
	v, err := parseString(value)
	if err != nil {
		return nil, err
	}

	if strings.IndexByte(v, 0) != -1 {
		return nil, errUnexpectedNullByte
	}

	filePath := make([]byte, len(v)+1)
	copy(filePath, v)
	return filePath, nil
}

func parseSocketAddress(value any) (unix.Sockaddr, error) {
	parsedValue, err := parseString(value)
	if err != nil {
		return nil, err
	}

	if strings.HasPrefix(parsedValue, "unix://") {
		parsedValue = parsedValue[len("unix://"):]
		sockaddr := &unix.SockaddrUnix{Name: parsedValue}
		return sockaddr, nil
	}

	host, port, err := net.SplitHostPort(parsedValue)
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

	var zoneID uint32
	if zoneIndex := strings.IndexRune(host, '%'); zoneIndex != -1 {
		zone := host[zoneIndex+1:]
		host = host[:zoneIndex]
		if zoneID, err = parseZoneID(zone); err != nil {
			return nil, fmt.Errorf("cannot parse %q zone: %w", zone, err)
		}
	}

	addr := net.ParseIP(host)
	if addr == nil {
		return nil, fmt.Errorf("cannot parse %q IP address", host)
	}

	if isIPv6 := strings.ContainsRune(host, ':'); isIPv6 {
		sockaddr := &unix.SockaddrInet6{
			Port:   int(portNumber),
			ZoneId: zoneID,
			Addr:   [16]byte(addr),
		}
		return sockaddr, nil
	}

	sockaddr := &unix.SockaddrInet4{
		Port: int(portNumber),
		Addr: [4]byte(addr.To4()),
	}
	return sockaddr, nil
}

// parseZoneID returns the interface index identified by the provided IPv6 zone, which can be either a numeric index or
// an interface name.
func parseZoneID(zone string) (uint32, error) {
	if zoneID, err := strconv.ParseUint(zone, 10, 32); err == nil {
		return uint32(zoneID), nil
	}

	iface, err := net.InterfaceByName(zone)
	if err != nil {
		return 0, err
	}

	return uint32(iface.Index), nil //nolint:gosec // Disable G115
}

func parseSingleValue(value any, valuesMap map[string]int) (int, error) {
	switch value := value.(type) {
	case uint64:
		return int(value), nil //nolint:gosec // Disable G115
	case string:
		if parsedValue, ok := valuesMap[value]; ok {
			return parsedValue, nil
		}
		return strconv.Atoi(value)
	default:
		return 0, errMustBeStringOrUint64
	}
}

func parseFlags(value any, flagsMap map[string]int) (int, error) {
	switch value := value.(type) {
	case uint64:
		return int(value), nil //nolint:gosec // Disable G115
	case string:
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
	default:
		return 0, errMustBeStringOrUint64
	}
}

func parseMap(value any) (map[string]any, error) {
	rawArgs, ok := value.(map[string]any)
	if !ok {
		return nil, errMustBeMap
	}

	return rawArgs, nil
}
