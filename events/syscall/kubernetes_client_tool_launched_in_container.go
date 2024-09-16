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
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(
	KubernetesClientToolLaunchedInContainer,
	events.WithDisabled(), // this rules is not included in falco_rules.yaml (stable rules), so disable the action
)

func KubernetesClientToolLaunchedInContainer(h events.Helper) error {
	if !h.InContainer() {
		return &events.ErrSkipped{
			Reason: "only applicable to containers",
		}
	}

	kubectl, err := exec.LookPath("kubectl")
	// if not present, create dummy kubectl executable
	if err != nil {
		// create a unique temp directory
		tmpDir, err := os.MkdirTemp("", "falco-event-generator-syscall-KubernetesClientToolLaunchedInContainer-")
		if err != nil {
			return err
		}
		defer func() {
			if err := os.RemoveAll(tmpDir); err != nil {
				h.Log().WithError(err).Error("failed to remove temp directory")
			}
		}()

		kubectl = filepath.Join(tmpDir, "kubectl")

		// create executable script file
		if err := os.WriteFile(kubectl, []byte("#!/bin/sh\n\necho 'hello world'\n"), os.FileMode(0755)); err != nil {
			return err
		}
	}

	cmd := exec.Command(kubectl)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}

	return nil
}
