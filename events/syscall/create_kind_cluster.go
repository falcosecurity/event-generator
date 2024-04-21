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
	cmd := exec.Command("kind", "create", "cluster", "--kubeconfig", kubeConfigPath)
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
