// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 The Falco Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package builder

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/docker/docker/api/types"
	dockercontainer "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	dockerimage "github.com/docker/docker/api/types/image"
	dockerclient "github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/go-logr/logr"

	"github.com/falcosecurity/event-generator/pkg/container"
)

// config stores the container builder underlying configuration.
type config struct {
	unixSocketURL       string
	baseImageName       string
	baseImagePullPolicy ImagePullPolicy
}

// ImagePullPolicy is the policy defining how to pull an image.
type ImagePullPolicy int

const (
	// ImagePullPolicyAlways specifies that the image must always be pulled from remote.
	ImagePullPolicyAlways ImagePullPolicy = iota
	// ImagePullPolicyNever specifies that the image must always be searched from the locally available images.
	ImagePullPolicyNever
	// ImagePullPolicyIfNotPresent specifies that the image must be pull from remote only if it not locally available.
	ImagePullPolicyIfNotPresent
)

// Option for configuring the container builder.
type Option interface {
	apply(*config) error
}

// funcOption is an implementation of Option storing a function that implements the requested apply method behavior.
type funcOption struct {
	f func(*config) error
}

func (cfo *funcOption) apply(c *config) error {
	return cfo.f(c)
}

// newFuncOption is a helper function to create a new funcOption from a function.
func newFuncOption(f func(*config) error) *funcOption {
	return &funcOption{f: f}
}

// WithUnixSocketURL allows to specify the unix socket URL of the local container runtime server.
// E.g.: unix:///run/docker.sock.
func WithUnixSocketURL(unixSocketURL string) Option {
	return newFuncOption(func(c *config) error {
		c.unixSocketURL = unixSocketURL
		return nil
	})
}

// WithBaseImageName allows to specify the name of the base image used to create the container.
func WithBaseImageName(baseImage string) Option {
	return newFuncOption(func(c *config) error {
		c.baseImageName = baseImage
		return nil
	})
}

// WithBaseImagePullPolicy allows to specify the pull policy for obtaining the base image.
func WithBaseImagePullPolicy(policy ImagePullPolicy) Option {
	return newFuncOption(func(c *config) error {
		c.baseImagePullPolicy = policy
		return nil
	})
}

var defaultConfig = &config{
	unixSocketURL:       "unix:///run/docker.sock",
	baseImageName:       "docker.io/falcosecurity/event-generator:latest",
	baseImagePullPolicy: ImagePullPolicyAlways,
}

// builder is an implementation of container.Builder leveraging docker.
type builder struct {
	config
	logger        logr.Logger
	namespaceName string
	imageName     string
	containerName string
	env           []string
	entrypoint    []string
}

// Verify that builder implements container.Builder interface.
var _ container.Builder = (*builder)(nil)

// New creates a new docker container builder.
func New(options ...Option) (container.Builder, error) {
	b := &builder{config: *defaultConfig}
	for _, opt := range options {
		if err := opt.apply(&b.config); err != nil {
			return nil, fmt.Errorf("error applying option: %w", err)
		}
	}
	return b, nil
}

func (b *builder) SetLogger(logger logr.Logger) {
	b.logger = logger
}

func (b *builder) SetImageName(name string) {
	b.imageName = name
}

func (b *builder) SetContainerName(name string) {
	b.containerName = name
}

func (b *builder) SetEnv(env []string) {
	b.env = env
}

func (b *builder) SetEntrypoint(entrypoint []string) {
	b.entrypoint = entrypoint
}

const (
	defaultContainerName = "event-generator"
)

var (
	defaultEntrypoint = []string{"/bin/event-generator"}
)

func (b *builder) Build() container.Container {
	baseImageName := b.baseImageName

	// If the image name is not provided, default it to the base image name.
	var imageName string
	if b.imageName != "" {
		imageName = b.imageName
	} else {
		imageName = baseImageName
	}

	// If the container name is not provided, default it.
	var containerName string
	if b.containerName != "" {
		containerName = b.containerName
	} else {
		containerName = defaultContainerName
	}

	// If the container entrypoint is not provided, default it.
	var entrypoint []string
	if b.entrypoint != nil {
		entrypoint = b.entrypoint
	} else {
		entrypoint = defaultEntrypoint
	}

	cont := &dockerContainer{
		logger:              b.logger,
		unixSocketURL:       b.unixSocketURL,
		baseImageName:       baseImageName,
		baseImagePullPolicy: b.baseImagePullPolicy,
		imageName:           imageName,
		containerName:       containerName,
		env:                 b.env,
		entrypoint:          entrypoint,
	}
	return cont
}

// dockerContainer is an implementation of a docker container.Container.
type dockerContainer struct {
	logger              logr.Logger
	unixSocketURL       string
	baseImageName       string
	baseImagePullPolicy ImagePullPolicy
	imageName           string
	containerName       string
	env                 []string
	entrypoint          []string

	// started is true if the container has been started; false otherwise.
	started bool
	// client is the client used to interact with the docker runtime.
	client *dockerclient.Client
	// containerID is the ID of the created docker container.
	containerID string
	// baseImageTagged is true if the base image has been tagged with the value specified in imageName; false otherwise.
	baseImageTagged bool
	// containerAttachOpHijackedResponse is the response obtained while performing the container attach operation. This
	// operation is needed in order to perform hijacking stdout/stderr container streams, which in turn are supposed to
	// be copied to the current process corresponding streams.
	containerAttachOpHijackedResponse *types.HijackedResponse
	// streamsCopyFinishedCh is a channel that is closed when the corresponding goroutine finishes to copy the container
	// stdout/stderr streams to the current process corresponding streams.
	streamsCopyFinishedCh chan struct{}
}

var (
	errContainerAlreadyStarted = fmt.Errorf("container already started")
	errContainerNotStarted     = fmt.Errorf("container not started")
)

func (c *dockerContainer) Start(ctx context.Context) (err error) {
	if c.started {
		return errContainerAlreadyStarted
	}

	defer func() {
		if err != nil {
			c.teardown(ctx, true)
		}
	}()

	logger := c.logger

	// Create docker client.
	client, err := dockerclient.NewClientWithOpts(dockerclient.WithHost(c.unixSocketURL),
		dockerclient.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("error client docker client: %w", err)
	}
	c.client = client

	// Retrieve base image.
	baseImageName := c.baseImageName
	if err := pullImage(ctx, client, baseImageName, c.baseImagePullPolicy); err != nil {
		return fmt.Errorf("error pulling base image %q: %w", baseImageName, err)
	}
	logger.V(1).Info("Pulled base image", "imageName", baseImageName)

	imageName := c.imageName
	// If the base image name is different from the required image name, tag the base image using the new name.
	if imageName != baseImageName {
		if err := client.ImageTag(ctx, baseImageName, imageName); err != nil {
			return fmt.Errorf("error tagging image %q as %q: %w", baseImageName, imageName, err)
		}
		c.baseImageTagged = true
		logger.V(1).Info("Tagged image", "baseImageName", baseImageName, "imageName", imageName)
	}

	// Create the container.
	containerID, err := c.createContainer(ctx, client, imageName)
	if err != nil {
		return fmt.Errorf("error creating container: %w", err)
	}
	c.containerID = containerID
	logger = logger.WithValues("containerID", containerID, "containerName", c.containerName)
	logger.V(1).Info("Created container")

	// Set up container attach options
	attachOptions := dockercontainer.AttachOptions{Stream: true, Stdout: true, Stderr: true}
	hijackedResponse, err := client.ContainerAttach(ctx, containerID, attachOptions)
	if err != nil {
		return fmt.Errorf("error attaching to container: %w", err)
	}
	c.containerAttachOpHijackedResponse = &hijackedResponse
	logger.V(1).Info("Attached container to read stdout/stderr streams")

	// Start the container.
	if err := client.ContainerStart(ctx, containerID, dockercontainer.StartOptions{}); err != nil {
		hijackedResponse.Close()
		return fmt.Errorf("error starting container: %w", err)
	}
	logger.V(1).Info("Started container")

	c.streamsCopyFinishedCh = make(chan struct{})
	go func(logger logr.Logger, hijackedResponse *types.HijackedResponse) {
		defer close(c.streamsCopyFinishedCh)
		if _, err := stdcopy.StdCopy(os.Stdout, os.Stderr, hijackedResponse.Reader); err != nil {
			logger.Error(err, "Error copying container stdout/stderr streams")
		}
	}(logger, &hijackedResponse)

	c.started = true
	return nil
}

// createContainer creates the container using the image associated with the provided name and the provided docker
// client, configuring it as specified in the underlying configuration. It returns the ID of the created container.
func (c *dockerContainer) createContainer(ctx context.Context, client *dockerclient.Client, imageName string) (string,
	error) {
	containerConfig := &dockercontainer.Config{
		AttachStdout: true,
		AttachStderr: true,
		Env:          c.env,
		Image:        imageName,
		Entrypoint:   c.entrypoint,
	}
	hostConfig := &dockercontainer.HostConfig{AutoRemove: true, Privileged: true}
	response, err := client.ContainerCreate(ctx, containerConfig, hostConfig, nil, nil, c.containerName)
	if err != nil {
		return "", err
	}

	return response.ID, nil
}

// teardown reverts all operations performed during Start execution.
func (c *dockerContainer) teardown(ctx context.Context, mustStopContainer bool) {
	defer func() {
		c.started = false
	}()

	client := c.client
	// If the client is nil, we are sure that the other fields are uninitialized, so simply return.
	if client == nil {
		return
	}

	logger := c.logger

	// Close the response hijacking stdout/stderr container streams which were supposed to be copied to the current
	// process corresponding streams.
	if hijackedResponse := c.containerAttachOpHijackedResponse; hijackedResponse != nil {
		hijackedResponse.Close()
		hijackedResponse = nil
	}

	// Ensure goroutine finished to copy stdout/stderr container streams.
	if c.streamsCopyFinishedCh != nil {
		<-c.streamsCopyFinishedCh
		c.streamsCopyFinishedCh = nil
	}

	if containerID := c.containerID; containerID != "" && mustStopContainer {
		logger := logger.WithValues("containerID", containerID, "containerName", c.containerName)
		if err := client.ContainerStop(ctx, containerID, dockercontainer.StopOptions{}); err != nil {
			logger.Error(err, "Error stopping container")
		} else {
			logger.V(1).Info("Stopped container")
		}
		c.containerID = ""
	}

	// Notice: no need to remove container as docker automatically removes it when it exists.

	if c.baseImageTagged {
		imageTag := c.imageName
		logger := logger.WithValues("imageTag", imageTag)
		if _, err := client.ImageRemove(ctx, imageTag, dockerimage.RemoveOptions{}); err != nil {
			logger.Error(err, "Error removing base image tag")
		} else {
			logger.V(1).Info("Removed base image tag")
		}
		c.baseImageTagged = false
	}

	if err := client.Close(); err != nil {
		logger.Error(err, "Error closing docker client")
	} else {
		logger.V(1).Info("Closed docker client")
	}
	c.client = nil
}

var errImageNotFoundLocally = fmt.Errorf("image not found locally")

// pullImage pulls the image with the provided image name, leveraging the provided docker client and using the provided
// image pull policy.
func pullImage(ctx context.Context, client *dockerclient.Client, imageName string, policy ImagePullPolicy) error {
	switch policy {
	case ImagePullPolicyAlways:
		if err := pullRemoteImage(ctx, client, imageName); err != nil {
			return fmt.Errorf("error pulling from remote: %w", err)
		}
		return nil
	case ImagePullPolicyNever:
		// First try locally.
		isAvailable, err := isImageLocallyAvailable(ctx, client, imageName)
		if err != nil {
			return fmt.Errorf("error verifying if the image is available locally: %w", err)
		}
		if !isAvailable {
			return errImageNotFoundLocally
		}
		return nil
	case ImagePullPolicyIfNotPresent:
		// First try locally.
		isAvailable, err := isImageLocallyAvailable(ctx, client, imageName)
		if err != nil {
			return fmt.Errorf("error verifying if the image is available locally: %w", err)
		}

		if isAvailable {
			return nil
		}

		// Otherwise, try to pull it from remote.
		if err := pullRemoteImage(ctx, client, imageName); err != nil {
			return fmt.Errorf("error pulling from remote: %w", err)
		}
		return nil
	default:
		panic(fmt.Sprintf("unknown image pull policy %q", policy))
	}
}

// pullRemoteImage requests docker to pull the image with the provided image name from the remote registry, leveraging
// the provided docker client.
func pullRemoteImage(ctx context.Context, client *dockerclient.Client, imageName string) error {
	reader, err := client.ImagePull(ctx, imageName, dockerimage.PullOptions{})
	if err != nil {
		return err
	}
	defer reader.Close()

	// Parse the response to ensure it doesn't contain any error.
	decoder := json.NewDecoder(reader)
	for {
		var message map[string]any
		if err := decoder.Decode(&message); err == io.EOF {
			return nil
		} else if err != nil {
			return fmt.Errorf("error decoding image pull response: %w", err)
		}

		if errMsg, ok := message["error"]; ok {
			return fmt.Errorf("error in image pull response: %s", errMsg)
		}
	}
}

// isImageLocallyAvailable returns, leveraging the provided docker client, a boolean indicating if an image with the
// provided name is locally available.
func isImageLocallyAvailable(ctx context.Context, client *dockerclient.Client, imageName string) (bool, error) {
	filterArgs := filters.NewArgs()
	filterArgs.Add("reference", imageName)
	images, err := client.ImageList(ctx, dockerimage.ListOptions{Filters: filterArgs})
	if err != nil {
		return false, fmt.Errorf("error retrieving image list: %w", err)
	}

	return len(images) != 0, nil
}

func (c *dockerContainer) Wait(ctx context.Context) error {
	if !c.started {
		return errContainerNotStarted
	}

	defer c.teardown(ctx, false)

	// Wait for the container to exit and get the exit status.
	responseCh, errCh := c.client.ContainerWait(ctx, c.containerID, dockercontainer.WaitConditionNotRunning)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh: // The returned error is always different from nil
		return fmt.Errorf("error waiting for container: %w", err)
	case response := <-responseCh:
		if exitErr := response.Error; exitErr != nil {
			return fmt.Errorf("error waiting for process: %s", exitErr.Message)
		}

		// The container is automatically removed by docker: just let the user know it.
		defer c.logger.V(1).Info("Removed container", "containerID", c.containerID)
		if exitCode := response.StatusCode; exitCode != 0 {
			return fmt.Errorf("container exited with non-zero exit code (%d)", exitCode)
		}

		return nil
	}
}
