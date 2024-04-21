package syscall

import (
	"context"
	"fmt"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

func deleteTestPod(kubeConfigPath string) {
	config, _ := clientcmd.BuildConfigFromFlags("", kubeConfigPath)
	clientset, _ := kubernetes.NewForConfig(config)

	err := clientset.CoreV1().Pods("default").Delete(context.TODO(), "test-pod", metav1.DeleteOptions{})
	if err != nil {
		fmt.Println("Error deleting test pod:", err)
	} else {
		fmt.Println("Test pod deleted successfully.")
	}
}
