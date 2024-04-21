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
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"time"
)

func defaultServiceAccount(clientset *kubernetes.Clientset) {
	_, err := clientset.CoreV1().ServiceAccounts("default").Get(context.TODO(), "default", metav1.GetOptions{})
	if err != nil {
		fmt.Println("Creating default service account...")
		_, _ = clientset.CoreV1().ServiceAccounts("default").Create(context.TODO(), &v1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
		}, metav1.CreateOptions{})
		fmt.Println("Default service account created successfully.")
	} else {
		fmt.Println("Default service account already exists.")
	}
}

func createTestPod(kubeConfigPath string) {
	config, _ := clientcmd.BuildConfigFromFlags("", kubeConfigPath)
	clientset, _ := kubernetes.NewForConfig(config)
	defaultServiceAccount(clientset)
	_, _ = clientset.CoreV1().Pods("default").Create(context.TODO(), newTestPod(), metav1.CreateOptions{})
	fmt.Println("Test pod created successfully.")
	verifyPodAndContainerRunning(kubeConfigPath)
}

// Adjust it as per requirement or you can create new pods/containers.
func newTestPod() *v1.Pod {
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pod"},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name:    "test-container",
					Image:   "busybox",
					Command: []string{"/bin/sh", "-c", "touch /tmp/created-by-event-generator.txt; sleep 60;"},				
				},
			},
			ServiceAccountName: "default", // Specify the default service account
		},
	}
}

func verifyPodAndContainerRunning(kubeConfigPath string) {
	config, _ := clientcmd.BuildConfigFromFlags("", kubeConfigPath)
	// Create a new Kubernetes client
	clientset, _ := kubernetes.NewForConfig(config)
	// Wait for the pod to be in the running state
	for {
		pod, _ := clientset.CoreV1().Pods("default").Get(context.TODO(), "test-pod", metav1.GetOptions{})
		if pod.Status.Phase == v1.PodRunning {
			break
		}
		time.Sleep(1 * time.Second)
	}
	fmt.Println("Test pod and container are running.")
}