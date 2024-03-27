//go:build linux
// +build linux

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
    "fmt"
    "os/exec"
	"math/rand"
    "github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(GenerateUnexpectedUDPTraffic)

func GenerateUnexpectedUDPTraffic(h events.Helper) error {
    // Choose a random port number
    port := randInt(1024, 65535)

    // Execute the command to send UDP packets
	message := "UDP traffic"
    cmd := exec.Command("echo", message, "|", "nc", "-u", "127.0.0.1", fmt.Sprintf("%d", port))
    err := cmd.Run()
    if err != nil {
        return err
    }

    // Log the event
    h.Log().Infof("Unexpected UDP Traffic Seen on port %d", port)

    return nil
}

// randInt generates a random integer between min and max.
func randInt(min, max int) int {
    return min + rand.Intn(max-min+1)
}
