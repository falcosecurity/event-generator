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

	"github.com/falcosecurity/event-generator/pkg/test/step/syscall"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/connect"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/dup"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/dup2"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/dup3"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/finitmodule"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/initmodule"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/kill"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/link"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/linkat"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/open"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/openat"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/openat2"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/read"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/sendto"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/socket"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/symlink"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/symlinkat"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/write"
)

// builder is an implementation of syscall.Builder.
type builder struct{}

// Verify that builder implements syscall.Syscall interface.
var _ syscall.Builder = (*builder)(nil)

// New creates a new builder.
func New() syscall.Builder {
	return &builder{}
}

func (b *builder) Build(name syscall.Name, stepName string, description *syscall.Description) (syscall.Syscall, error) {
	rawArgs := description.RawArgs
	fieldBindings := description.FieldBindings
	errDecorator := errorDecorator(name)
	switch name {
	case syscall.NameWrite:
		return errDecorator(write.New(stepName, rawArgs, fieldBindings))
	case syscall.NameRead:
		return errDecorator(read.New(stepName, rawArgs, fieldBindings))
	case syscall.NameDup:
		return errDecorator(dup.New(stepName, rawArgs, fieldBindings))
	case syscall.NameDup2:
		return errDecorator(dup2.New(stepName, rawArgs, fieldBindings))
	case syscall.NameDup3:
		return errDecorator(dup3.New(stepName, rawArgs, fieldBindings))
	case syscall.NameConnect:
		return errDecorator(connect.New(stepName, rawArgs, fieldBindings))
	case syscall.NameSocket:
		return errDecorator(socket.New(stepName, rawArgs, fieldBindings))
	case syscall.NameOpen:
		return errDecorator(open.New(stepName, rawArgs, fieldBindings))
	case syscall.NameOpenAt:
		return errDecorator(openat.New(stepName, rawArgs, fieldBindings))
	case syscall.NameOpenAt2:
		return errDecorator(openat2.New(stepName, rawArgs, fieldBindings))
	case syscall.NameLink:
		return errDecorator(link.New(stepName, rawArgs, fieldBindings))
	case syscall.NameLinkAt:
		return errDecorator(linkat.New(stepName, rawArgs, fieldBindings))
	case syscall.NameSymLink:
		return errDecorator(symlink.New(stepName, rawArgs, fieldBindings))
	case syscall.NameSymLinkAt:
		return errDecorator(symlinkat.New(stepName, rawArgs, fieldBindings))
	case syscall.NameInitModule:
		return errDecorator(initmodule.New(stepName, rawArgs, fieldBindings))
	case syscall.NameFinitModule:
		return errDecorator(finitmodule.New(stepName, rawArgs, fieldBindings))
	case syscall.NameSendTo:
		return errDecorator(sendto.New(stepName, rawArgs, fieldBindings))
	case syscall.NameKill:
		return errDecorator(kill.New(stepName, rawArgs, fieldBindings))
	default:
		return nil, fmt.Errorf("unknown syscall %q", name)
	}
}

type buildError struct {
	syscallName syscall.Name
	err         error
}

func (e *buildError) Error() string {
	return fmt.Sprintf("error building %q syscall test step: %v", e.syscallName, e.err)
}

func errorDecorator(name syscall.Name) func(syscall.Syscall, error) (syscall.Syscall, error) {
	return func(s syscall.Syscall, err error) (syscall.Syscall, error) {
		if err != nil {
			return nil, &buildError{syscallName: name, err: err}
		}

		return s, nil
	}
}
