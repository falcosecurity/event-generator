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

	"github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(NetworkActivity)

// NetworkActivity tries to connect to an andress.
func NetworkActivity(h events.Helper) error {
	conn, err := net.Dial("udp", "10.2.3.4:8192")
	defer func() {
		if err := conn.Close(); err != nil {
			h.Log().WithError(err).Error("failed to close connection")
		}
	}()

	return err
}
