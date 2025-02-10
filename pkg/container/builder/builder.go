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
	"fmt"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/cio"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/oci"
	"github.com/go-logr/logr"

	"github.com/falcosecurity/event-generator/pkg/container"
)

// config stores the container builder underlying configuration.
type config struct {
	unixSocketPath      string
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

// WithUnixSocketPath allows to specify the unix socket path of the local container runtime server.
func WithUnixSocketPath(unixSocketPath string) Option {
	return newFuncOption(func(c *config) error {
		c.unixSocketPath = unixSocketPath
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
	unixSocketPath:      "/run/containerd/containerd.sock",
	baseImageName:       "docker.io/falcosecurity/event-generator:latest",
	baseImagePullPolicy: ImagePullPolicyAlways,
}

// builder is an implementation of container.Builder leveraging containerd.
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

// New creates a new containerd container builder.
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

func (b *builder) SetNamespaceName(name string) {
	b.namespaceName = name
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
	defaultNamespaceName = "event-generator"
	defaultContainerName = "event-generator"
)

var (
	defaultEntrypoint = []string{"/bin/event-generator"}
)

func (b *builder) Build() container.Container {
	// If the namespace is not provided, default it.
	var namespaceName string
	if b.namespaceName != "" {
		namespaceName = b.namespaceName
	} else {
		namespaceName = defaultNamespaceName
	}

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

	cont := &containerdContainer{
		logger:              b.logger,
		unixSocketPath:      b.unixSocketPath,
		namespaceName:       namespaceName,
		baseImageName:       baseImageName,
		baseImagePullPolicy: b.baseImagePullPolicy,
		imageName:           imageName,
		containerName:       containerName,
		env:                 b.env,
		entrypoint:          entrypoint,
	}
	return cont
}

// containerdContainer is an implementation of a containerd container.Container.
type containerdContainer struct {
	logger              logr.Logger
	unixSocketPath      string
	namespaceName       string
	baseImageName       string
	baseImagePullPolicy ImagePullPolicy
	imageName           string
	containerName       string
	env                 []string
	entrypoint          []string

	// started is true if the container has been started; false otherwise.
	started bool
	// client is the client used to interact with the containerd runtime.
	client *containerd.Client
	// createdImage is the image created if imageName is different from baseImageName. If they are equal, createdImage
	// is nil.
	createdImage containerd.Image
	// container is the containerd container.
	container containerd.Container
	// task is the task associated with the container.
	task containerd.Task
}

var (
	errContainerAlreadyStarted = fmt.Errorf("container already started")
	errContainerNotStarted     = fmt.Errorf("container not started")
)

func (c *containerdContainer) Start(ctx context.Context) (err error) {
	if c.started {
		return errContainerAlreadyStarted
	}

	defer func() {
		if err != nil {
			c.teardown(ctx)
		}
	}()

	logger := c.logger
	namespace := c.namespaceName

	// Create containerd client.
	client, err := containerd.New(c.unixSocketPath, containerd.WithDefaultNamespace(namespace))
	if err != nil {
		return fmt.Errorf("error client containerd client: %w", err)
	}
	c.client = client

	// Set namespace into context to default it into subsequent requests to client.
	ctx = namespaces.WithNamespace(ctx, namespace)

	// Retrieve base image.
	baseImageName := c.baseImageName
	image, err := getImage(ctx, client, baseImageName, c.baseImagePullPolicy)
	if err != nil {
		return fmt.Errorf("error getting image %q: %w", baseImageName, err)
	}
	logger.V(1).Info("Retrieved base image", "imageName", baseImageName)

	imageName := c.imageName
	// If the base image name is different from the required name for the image that is going to be used for the
	// container, create a new image with the required name from the base image.
	if imageName != baseImageName {
		metadata := image.Metadata()
		metadata.Name = imageName
		imageService := client.ImageService()
		var createdImage images.Image
		createdImage, err = imageService.Create(ctx, metadata)
		if err != nil {
			return fmt.Errorf("error tagging image %q as %q: %w", baseImageName, imageName, err)
		}
		logger.V(1).Info("Tagged image", "baseImageName", baseImageName, "imageName", imageName)

		// Set image to the new created image.
		image = containerd.NewImage(client, createdImage)
		c.createdImage = image
	}

	// Create the container.
	cont, err := c.createContainer(ctx, client, image)
	if err != nil {
		return fmt.Errorf("error creating container: %w", err)
	}
	c.container = cont
	logger.V(1).Info("Created container", "containerName", c.containerName)

	// Create a new task for the container.
	task, err := cont.NewTask(ctx, cio.NewCreator(cio.WithStdio), containerd.WithRuntimePath("io.containerd.runc.v1"))
	if err != nil {
		return fmt.Errorf("error creating new task: %w", err)
	}
	c.task = task
	logger.V(1).Info("Created task")

	if err := task.Start(ctx); err != nil {
		return fmt.Errorf("error starting task: %w", err)
	}

	c.started = true
	return nil
}

// createContainer creates the container using the provided image and containerd client, configuring it as specified in
// the underlying configuration.
func (c *containerdContainer) createContainer(ctx context.Context, client *containerd.Client,
	image containerd.Image) (containerd.Container, error) {
	specOpts := []oci.SpecOpts{
		oci.WithPrivileged,
		oci.WithEnv(c.env),
	}
	if entrypoint := c.entrypoint; entrypoint != nil {
		specOpts = append(specOpts, oci.WithProcessArgs(entrypoint...))
	}
	containerOptions := []containerd.NewContainerOpts{
		containerd.WithImage(image),
		containerd.WithNewSnapshot(fmt.Sprintf("%s-rootfs", image.Name()), image),
		containerd.WithNewSpec(specOpts...),
	}
	return client.NewContainer(ctx, c.containerName, containerOptions...)
}

// teardown reverts all operations performed during Start execution.
func (c *containerdContainer) teardown(ctx context.Context) {
	defer func() {
		c.started = false
	}()

	client := c.client
	// If the client is nil, we are sure that the other fields are uninitialized, so simply return.
	if client == nil {
		return
	}

	logger := c.logger

	if task := c.task; task != nil {
		if _, err := task.Delete(ctx); err != nil {
			logger.Error(err, "Error deleting container task")
		} else {
			logger.V(1).Info("Deleted container task")
		}
		c.task = nil
	}

	if cont := c.container; cont != nil {
		logger := logger.WithValues("containerName", cont.ID())
		if err := cont.Delete(ctx, containerd.WithSnapshotCleanup); err != nil {
			logger.Error(err, "Error deleting container")
		} else {
			logger.V(1).Info("Deleted container")
		}
		c.container = nil
	}

	if createdImage := c.createdImage; createdImage != nil {
		imageService := client.ImageService()
		imageName := createdImage.Name()
		logger := logger.WithValues("imageName", imageName)
		if err := imageService.Delete(ctx, imageName); err != nil {
			logger.Error(err, "Error deleting image")
		} else {
			logger.V(1).Info("Deleted image")
		}
		c.createdImage = nil
	}

	if err := client.Close(); err != nil {
		logger.Error(err, "Error closing containerd client")
	} else {
		logger.V(1).Info("Closed containerd client")
	}
	c.client = nil
}

// getImage returns the image with the provided image name, leveraging the provided containerd client and using the
// provided image pull policy.
func getImage(ctx context.Context, client *containerd.Client, imageName string,
	policy ImagePullPolicy) (containerd.Image, error) {
	switch policy {
	case ImagePullPolicyAlways:
		return client.Pull(ctx, imageName)
	case ImagePullPolicyNever:
		return client.GetImage(ctx, imageName)
	case ImagePullPolicyIfNotPresent:
		image, err := client.GetImage(ctx, imageName)
		if errdefs.IsNotFound(err) {
			return client.Pull(ctx, imageName)
		}
		return image, err
	default:
		panic(fmt.Sprintf("unknown image pull policy %q", policy))
	}
}

func (c *containerdContainer) Wait(ctx context.Context) error {
	if !c.started {
		return errContainerNotStarted
	}

	defer c.teardown(ctx)

	// Wait for the task to exit and get the exit status.
	exitStatusCh, err := c.task.Wait(ctx)
	if err != nil {
		return fmt.Errorf("error waiting for task: %w", err)
	}

	exitStatus := <-exitStatusCh
	if err := exitStatus.Error(); err != nil {
		return fmt.Errorf("error waiting for process: %w", err)
	}

	if exitCode := exitStatus.ExitCode(); exitCode != 0 {
		return fmt.Errorf("container exited with non-zero exit code (%d)", exitCode)
	}

	return nil
}
