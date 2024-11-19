// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 The Falco Authors
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
	"fmt"
	"os"

	"github.com/go-logr/logr"

	"github.com/falcosecurity/event-generator/pkg/test/loader"
	"github.com/falcosecurity/event-generator/pkg/test/resource"
	"github.com/falcosecurity/event-generator/pkg/test/resource/clientserver"
	"github.com/falcosecurity/event-generator/pkg/test/resource/fd/directory"
	"github.com/falcosecurity/event-generator/pkg/test/resource/fd/epoll"
	"github.com/falcosecurity/event-generator/pkg/test/resource/fd/event"
	"github.com/falcosecurity/event-generator/pkg/test/resource/fd/file"
	"github.com/falcosecurity/event-generator/pkg/test/resource/fd/inotify"
	"github.com/falcosecurity/event-generator/pkg/test/resource/fd/mem"
	"github.com/falcosecurity/event-generator/pkg/test/resource/fd/pipe"
	"github.com/falcosecurity/event-generator/pkg/test/resource/fd/signal"
	"github.com/falcosecurity/event-generator/pkg/test/resource/process"
)

// builder is an implementation of resource.Builder.
type builder struct{}

// Verify that builder implements resource.Builder interface.
var _ resource.Builder = (*builder)(nil)

// New creates a new builder.
func New() (resource.Builder, error) {
	return &builder{}, nil
}

func (b *builder) Build(logger logr.Logger, testResource *loader.TestResource) (resource.Resource, error) {
	resourceType := testResource.Type
	resourceName := testResource.Name
	logger = logger.WithValues("resourceType", resourceType)
	switch resourceType {
	case loader.TestResourceTypeClientServer:
		clientServerSpec, ok := testResource.Spec.(*loader.TestResourceClientServerSpec)
		if !ok {
			return nil, fmt.Errorf("cannot parse clientServer spec")
		}

		// TODO: remove the cast and use a dedicated type for l4Proto
		res := clientserver.New(logger, resourceName, string(clientServerSpec.L4Proto), clientServerSpec.Address)
		return res, nil
	case loader.TestResourceTypeFD:
		fdSpec, ok := testResource.Spec.(*loader.TestResourceFDSpec)
		if !ok {
			return nil, fmt.Errorf("cannot parse fd spec")
		}

		res, err := buildFD(logger, resourceName, fdSpec)
		if err != nil {
			return nil, fmt.Errorf("cannot build fd resource: %w", err)
		}

		return res, nil
	case loader.TestResourceTypeProcess:
		procSpec, ok := testResource.Spec.(*loader.TestResourceProcessSpec)
		if !ok {
			return nil, fmt.Errorf("cannot parse process spec")
		}

		res := buildProcess(logger, resourceName, procSpec)
		return res, nil
	default:
		return nil, fmt.Errorf("unknown test resource type %q", resourceType)
	}
}

// buildFD builds a fd test resource.
func buildFD(logger logr.Logger, resourceName string,
	fdSpec *loader.TestResourceFDSpec) (resource.Resource, error) {
	subtype := fdSpec.Subtype
	logger = logger.WithValues("fdSubtype", subtype)
	switch subtype {
	case loader.TestResourceFDSubtypeFile:
		subSpec, ok := fdSpec.Spec.(*loader.TestResourceFDFileSpec)
		if !ok {
			return nil, fmt.Errorf("cannot parse file spec")
		}

		return file.New(logger, resourceName, subSpec.FilePath), nil
	case loader.TestResourceFDSubtypeDirectory:
		subSpec, ok := fdSpec.Spec.(*loader.TestResourceFDDirectorySpec)
		if !ok {
			return nil, fmt.Errorf("cannot parse directory spec")
		}

		return directory.New(logger, resourceName, subSpec.DirPath), nil
	case loader.TestResourceFDSubtypePipe:
		if _, ok := fdSpec.Spec.(*loader.TestResourceFDPipeSpec); !ok {
			return nil, fmt.Errorf("cannot parse pipe spec")
		}

		return pipe.New(logger, resourceName), nil
	case loader.TestResourceFDSubtypeEvent:
		if _, ok := fdSpec.Spec.(*loader.TestResourceFDEventSpec); !ok {
			return nil, fmt.Errorf("cannot parse event spec")
		}

		return event.New(logger, resourceName), nil
	case loader.TestResourceFDSubtypeSignal:
		if _, ok := fdSpec.Spec.(*loader.TestResourceFDSignalSpec); !ok {
			return nil, fmt.Errorf("cannot parse signalfd spec")
		}

		return signal.New(logger, resourceName), nil
	case loader.TestResourceFDSubtypeEpoll:
		if _, ok := fdSpec.Spec.(*loader.TestResourceFDEpollSpec); !ok {
			return nil, fmt.Errorf("cannot parse eventpoll spec")
		}

		return epoll.New(logger, resourceName), nil
	case loader.TestResourceFDSubtypeInotify:
		if _, ok := fdSpec.Spec.(*loader.TestResourceFDInotifySpec); !ok {
			return nil, fmt.Errorf("cannot parse inotify spec")
		}

		return inotify.New(logger, resourceName), nil
	case loader.TestResourceFDSubtypeMem:
		subSpec, ok := fdSpec.Spec.(*loader.TestResourceFDMemSpec)
		if !ok {
			return nil, fmt.Errorf("cannot parse memfd spec")
		}

		return mem.New(logger, resourceName, subSpec.FileName), nil
	default:
		return nil, fmt.Errorf("unknown fd test resource subtype %q", subtype)
	}
}

func buildProcess(logger logr.Logger, resourceName string, procSpec *loader.TestResourceProcessSpec) resource.Resource {
	var simExePath, name, arg0, args string
	if procSpec.ExePath != nil {
		simExePath = *procSpec.ExePath
	}
	if procSpec.Name != nil {
		name = *procSpec.Name
	}
	if procSpec.Exe != nil {
		arg0 = *procSpec.Exe
	}
	if procSpec.Args != nil {
		args = *procSpec.Args
	}
	procEnv := buildProcEnv(procSpec.Env)
	return process.New(logger, resourceName, simExePath, name, arg0, args, procEnv)
}

func buildProcEnv(userEnv map[string]string) []string {
	env := os.Environ()

	// Add the user-provided environment variable.
	for key, value := range userEnv {
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}
	return env
}
