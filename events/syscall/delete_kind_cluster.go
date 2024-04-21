package syscall

import (
	"os"
	"os/exec"
)

func deleteKindCluster() error {
	cmd := exec.Command("kind", "delete", "cluster")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.Run()
	return nil
}
