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
    "os/exec"
    "github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(
    ContactCloudMetadataServiceFromContainer,
    events.WithDisabled(), // this rule is not included in falco_rules.yaml (stable rules), so disable the action
)

func ContactCloudMetadataServiceFromContainer(h events.Helper) error {
    if h.InContainer() {
        //This event works on GCP, AWS, and Azure using the common link-local IP address 169.254.169.254.
        cmd := exec.Command("timeout", "1s", "nc", "169.254.169.254", "80")
    
        if err := cmd.Run(); err != nil {
            return err
        }

        h.Log().Infof("Outbound connection to cloud instance metadata service")
    }
    return nil
}
