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
	"bytes"
	"fmt"
	"os"
	"os/exec"

	"github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(ExfiltratingArtifactsViaKubernetesControlPlane)

func ExfiltratingArtifactsViaKubernetesControlPlane(h events.Helper) error {
	kubeConfigPath, _ := createKindCluster()
	waitForClusterReadiness(kubeConfigPath)
	createTestPod(kubeConfigPath)
	copyFileFromContainer(kubeConfigPath)
	deleteTestPod(kubeConfigPath)
	defer deleteKindCluster()

	return nil
}

func copyFileFromContainer(kubeConfigPath string) {
	// Copy the file from the container to the host
	cmd := exec.Command("kubectl", "--kubeconfig", kubeConfigPath, "cp", "test-pod:/tmp/created-by-event-generator.txt", "/tmp/created-by-event-generator.txt")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Run()
	fmt.Println("File copied from container to host successfully.")
	os.Remove("/tmp/created-by-event-generator.txt")
}