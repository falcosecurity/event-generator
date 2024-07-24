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

package declarative

import (
	"context"
	"fmt"
	"os/exec"
)

type Hostrunner struct{}

func (r *Hostrunner) Setup(ctx context.Context, beforeScript string) error {
	if beforeScript != "" {
		if err := exec.Command("sh", "-c", beforeScript).Run(); err != nil {
			return fmt.Errorf("error executing before script: %v", err)
		}
	}
	return nil
}

func (r *Hostrunner) ExecuteStep(ctx context.Context, test Test) error {
	steps := test.Steps
	for _, step := range steps {
		switch step.Syscall {
		case "write":
			if err := WriteSyscall(step.Args["filepath"], step.Args["content"]); err != nil {
				return fmt.Errorf("write syscall failed with error: %v", err)
			}
		default:
			return fmt.Errorf("unsupported syscall: %s", step.Syscall)
		}
	}
	return nil
}

func (r *Hostrunner) Cleanup(ctx context.Context, afterScript string) error {
	if afterScript != "" {
		if err := exec.Command("sh", "-c", afterScript).Run(); err != nil {
			return fmt.Errorf("error executing after script: %v", err)
		}
	}
	return nil
}
