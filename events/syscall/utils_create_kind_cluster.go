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
	"context"
	"fmt"
	"github.com/falcosecurity/event-generator/events"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

func createKindCluster() (string, error) {
	_, err := exec.LookPath("kind")
	if err != nil {
		return "", &events.ErrSkipped{
			Reason: "'Exfiltrating Artifacts Via Kubernetes Control Plane' requires the 'kind' utility.",
		}
	}
	tempDir, _ := os.MkdirTemp("", "kind-cluster")
	kubeConfigPath := filepath.Join(tempDir, "kind-kubeconfig")
	cmd := exec.Command("kind", "create", "cluster", "--name", "cluster-created-by-event-generator", "--kubeconfig", kubeConfigPath)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		os.RemoveAll(tempDir)
		return "", fmt.Errorf("failed to create Kind cluster: %v", err)
	}
	return kubeConfigPath, nil
}

func waitForClusterReadiness(kubeConfigPath string) error {
	config, _ := clientcmd.BuildConfigFromFlags("", kubeConfigPath)
	clientset, _ := kubernetes.NewForConfig(config)

	fmt.Println("Waiting for cluster to be fully ready...")
	for {
		pods, _ := clientset.CoreV1().Pods("kube-system").List(context.TODO(), metav1.ListOptions{})

		allReady := true
		for _, pod := range pods.Items {
			if pod.Status.Phase != v1.PodRunning {
				allReady = false
				break
			}
		}
		if allReady {
			fmt.Println("All system pods are running.")
			break
		}
		fmt.Println("System pods not ready, waiting...")
		time.Sleep(10 * time.Second)
	}
	return nil
}
