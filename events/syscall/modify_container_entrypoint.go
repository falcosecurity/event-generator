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
    "os"

    "github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(
	ModifyContainerEntrypoint,
	events.WithDisabled(), // this rules is not included in falco_rules.yaml (stable rules), so disable the action
)

func ModifyContainerEntrypoint(h events.Helper) error {
    if h.InContainer() {
        // Open /proc/self/exe for writing
        file, err := os.OpenFile("/proc/self/exe", os.O_WRONLY, 0644)
        if err != nil {
            h.Log().WithError(err).Error("Failed to open /proc/self/exe for writing")
            return err
        }
        defer file.Close()
        // Write "written by event-generator" to /proc/self/exe
        data := []byte("written by event-generator")
        os.WriteFile("/proc/self/exe", data, 0644)


        h.Log().Info("Detect Potential Container Breakout Exploit (CVE-2019-5736)")
    }

    return nil
}