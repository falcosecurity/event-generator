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

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
)

// Common runner interface for runners like hostrunner, container-runner etc..
type Runner interface {
	Setup(beforeScript string) error
	ExecuteStep(step SyscallStep) error
	Cleanup(afterScript string) error
}

type Hostrunner struct{}

func (r *Hostrunner) Setup(beforeScript string) error {
	if beforeScript != "" {
		if err := exec.Command("sh", "-c", beforeScript).Run(); err != nil {
			return fmt.Errorf("error executing before script: %v", err)
		}
	}
	return nil
}

func (r *Hostrunner) ExecuteStep(step SyscallStep) error {
	switch step.Syscall {
	case "write":
		if err := WriteSyscall(step.Args["filepath"], step.Args["content"]); err != nil {
			return fmt.Errorf("write syscall failed with error: %v", err)
		}
	default:
		return fmt.Errorf("unsupported syscall: %s", step.Syscall)
	}
	return nil
}

func (r *Hostrunner) Cleanup(afterScript string) error {
	if afterScript != "" {
		if err := exec.Command("sh", "-c", afterScript).Run(); err != nil {
			return fmt.Errorf("error executing after script: %v", err)
		}
	}
	return nil
}

type Containerrunner struct {
	ContainerId string
	Image       string
}

func (r *Containerrunner) Setup(beforeScript string) error {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("error creating Docker Client: %v", err)
	}

	// Pull the image
	_, err = cli.ImagePull(context.Background(), r.Image, image.PullOptions{})
	if err != nil {
		return fmt.Errorf("error pulling Docker Image: %v", err)
	}

	// Create the container with name "alpine-container-by-event-generator"
	resp, err := cli.ContainerCreate(context.Background(),
		&container.Config{
			Image: r.Image,
			Cmd:   []string{"sh", "-c", beforeScript},
		}, nil, nil, nil, "alpine-container-by-event-generator")

	if err != nil {
		return fmt.Errorf("error creating Docker Container: %v", err)
	}

	// Store created container id
	r.ContainerId = resp.ID

	// Start the container
	err = cli.ContainerStart(context.Background(), r.ContainerId, container.StartOptions{})
	if err != nil {
		return fmt.Errorf("error starting Docker container: %v", err)
	}

	// Wait for the container to finish executing the beforescript
	// ContainerWait returns 2 channels
	// statusCh - receives the container exit status once it stops running
	// errCh - receives any error occurs while waiting for the container to stop
	statusCh, errCh := cli.ContainerWait(context.Background(), r.ContainerId, container.WaitConditionNotRunning)
	select {
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("error waiting for the docker container: %v", err)
		}
	case <-statusCh:
	}

	return nil
}

func (r *Containerrunner) ExecuteStep(step SyscallStep) error {
	return nil
}

func (r *Containerrunner) Cleanup(afterScript string) error {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("error creating Docker Client: %v", err)
	}

	// If there is any afterScript execute it before removing the container
	if afterScript != "" {
		cmd := []string{"sh", "-c", afterScript}
		execConfig := container.ExecOptions{
			Cmd: cmd,
		}

		execID, err := cli.ContainerExecCreate(context.Background(), r.ContainerId, execConfig)
		if err != nil {
			return fmt.Errorf("error creating Docker exec: %v", err)
		}

		err = cli.ContainerExecStart(context.Background(), execID.ID, container.ExecStartOptions{})
		if err != nil {
			return fmt.Errorf("error starting Docker exec: %v", err)
		}
	}

	err = cli.ContainerRemove(context.Background(), r.ContainerId, container.RemoveOptions{Force: true})
	if err != nil {
		return fmt.Errorf("error removing Docker container: %v", err)
	}
	return nil
}
