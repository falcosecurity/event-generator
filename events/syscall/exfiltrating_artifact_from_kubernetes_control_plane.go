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
