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
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
	"gopkg.in/yaml.v2"
)

type Containerrunner struct {
	ContainerId string
	Image       string
}

func (r *Containerrunner) Setup(ctx context.Context, beforeScript string) error {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("error creating Docker Client: %v", err)
	}

	// Pull the image
	pullRes, err := cli.ImagePull(ctx, r.Image, image.PullOptions{})
	if err != nil {
		return fmt.Errorf("error pulling Docker Image: %v", err)
	}

	// Read the response of body inorder to download the image
	defer pullRes.Close()
	_, err = io.Copy(io.Discard, pullRes)
	if err != nil {
		log.Fatal(err)
	}

	// Create the container with name "alpine-container-by-event-generator"
	resp, err := cli.ContainerCreate(ctx,
		&container.Config{
			Image: r.Image,
			Cmd:   []string{"sleep", "1h"},
		}, nil, nil, nil, "alpine-container-by-event-generator")

	if err != nil {
		return fmt.Errorf("error creating Docker Container: %v", err)
	}

	// Store created container id
	r.ContainerId = resp.ID

	// Path of the event-generator executable
	path_eg, err := os.Executable()
	if err != nil {
		return fmt.Errorf("error extracting path of event-generator executable")
	}

	tarReader, err := CreateTarReader(path_eg)
	if err != nil {
		return fmt.Errorf("error creating tar reader: %v", err)
	}

	err = cli.CopyToContainer(ctx, r.ContainerId, "/", tarReader, container.CopyToContainerOptions{})
	if err != nil {
		return fmt.Errorf("error copying file to container: %v", err)
	}

	// Start the container
	err = cli.ContainerStart(ctx, r.ContainerId, container.StartOptions{})
	if err != nil {
		return fmt.Errorf("error starting Docker container: %v", err)
	}
	return nil
}

func (r *Containerrunner) ExecuteStep(ctx context.Context, test Test) error {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("error creating Docker Client: %v", err)
	}

	// Create a yaml structure for given step
	test.Runner = "HostRunner" // Change container runner to host runner
	testFile := Tests{
		Tests: []Test{test},
	}

	// Marshall struct to yaml data
	yamldata, err := yaml.Marshal(testFile)
	if err != nil {
		return fmt.Errorf("error marshalling syscallstep input to yaml: %v", err)
	}

	// Write the yaml data to temporary file
	tempFile, err := os.CreateTemp("", "syscall-*.yaml")
	if err != nil {
		return fmt.Errorf("error creating temporary file: %v", err)
	}
	defer os.Remove(tempFile.Name())

	if _, err := tempFile.Write(yamldata); err != nil {
		return fmt.Errorf("error writing to temporary file: %v", err)
	}
	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("error closing temporary file: %w", err)
	}

	tarReader, err := CreateTarReader(tempFile.Name())
	if err != nil {
		return fmt.Errorf("error creating tar reader: %v", err)
	}

	err = cli.CopyToContainer(ctx, r.ContainerId, "/", tarReader, container.CopyToContainerOptions{})
	if err != nil {
		return fmt.Errorf("error copying yaml file to container: %v", err)
	}

	// Prepare the command to run the event-generator inside container
	yamlFileName := filepath.Base(tempFile.Name())
	cmd := []string{"/event-generator", "run", "declarative", "/" + yamlFileName}

	execConfig := container.ExecOptions{
		Cmd:          cmd,
		AttachStdout: true,
		AttachStderr: true,
	}

	execID, err := cli.ContainerExecCreate(ctx, r.ContainerId, execConfig)
	if err != nil {
		return fmt.Errorf("error creating Docker exec: %v", err)
	}

	err = cli.ContainerExecStart(ctx, execID.ID, container.ExecStartOptions{})
	if err != nil {
		return fmt.Errorf("error starting Docker exec: %v", err)
	}

	// Use this channel to wait for the exec instance to complete
	done := make(chan error, 1)
	go func() {
		for {
			inspectResp, err := cli.ContainerExecInspect(ctx, execID.ID)
			if err != nil {
				done <- fmt.Errorf("error inspecting Docker exec: %v", err)
				return
			}

			if !inspectResp.Running {
				if inspectResp.ExitCode != 0 {
					done <- fmt.Errorf("ExecuteStep failed with exit code %v", inspectResp.ExitCode)
				} else {
					done <- nil
				}
				return
			}
		}
	}()

	err = <-done
	return err
}

func (r *Containerrunner) Cleanup(ctx context.Context, afterScript string) error {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("error creating Docker Client: %v", err)
	}

	err = cli.ContainerRemove(ctx, r.ContainerId, container.RemoveOptions{Force: true})
	if err != nil {
		return fmt.Errorf("error removing Docker container: %v", err)
	}
	return nil
}
