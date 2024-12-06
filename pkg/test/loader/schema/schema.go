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

package schema

import (
	_ "embed"
	"fmt"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Embeds all required JSON schemas.
var (
	//go:embed jsonschemas/description.schema.json
	descriptionSchema string
	//go:embed jsonschemas/binding.schema.json
	bindingSchema string
	//go:embed jsonschemas/test.schema.json
	testSchema string
	//go:embed jsonschemas/context.schema.json
	contextSchema string
	//go:embed jsonschemas/resource.schema.json
	resourceSchema string
	//go:embed jsonschemas/resources/clientServer.schema.json
	clientServerResourceSchema string
	//go:embed jsonschemas/resources/fd.schema.json
	fdResourceSchema string
	//go:embed jsonschemas/resources/fd/file.schema.json
	fileFDResourceSchema string
	//go:embed jsonschemas/resources/fd/directory.schema.json
	directoryFDResourceSchema string
	//go:embed jsonschemas/resources/fd/pipe.schema.json
	pipeFDResourceSchema string
	//go:embed jsonschemas/resources/fd/event.schema.json
	eventFDResourceSchema string
	//go:embed jsonschemas/resources/fd/signalfd.schema.json
	signalfdFDResourceSchema string
	//go:embed jsonschemas/resources/fd/eventpoll.schema.json
	eventpollFDResourceSchema string
	//go:embed jsonschemas/resources/fd/inotify.schema.json
	inotifyFDResourceSchema string
	//go:embed jsonschemas/resources/fd/memfd.schema.json
	memfdFDResourceSchema string
	//go:embed jsonschemas/resources/process.schema.json
	processResourceSchema string
	//go:embed jsonschemas/step.schema.json
	stepSchema string
	//go:embed jsonschemas/steps/syscall.schema.json
	syscallStepSchema string
	//go:embed jsonschemas/steps/syscalls/connect.schema.json
	connectSyscallStepSchema string
	//go:embed jsonschemas/steps/syscalls/dup.schema.json
	dupSyscallStepSchema string
	//go:embed jsonschemas/steps/syscalls/dup2.schema.json
	dup2SyscallStepSchema string
	//go:embed jsonschemas/steps/syscalls/dup3.schema.json
	dup3SyscallStepSchema string
	//go:embed jsonschemas/steps/syscalls/finitModule.schema.json
	finitModuleSyscallStepSchema string
	//go:embed jsonschemas/steps/syscalls/initModule.schema.json
	initModuleSyscallStepSchema string
	//go:embed jsonschemas/steps/syscalls/kill.schema.json
	killSyscallStepSchema string
	//go:embed jsonschemas/steps/syscalls/link.schema.json
	linkSyscallStepSchema string
	//go:embed jsonschemas/steps/syscalls/linkAt.schema.json
	linkatSyscallStepSchema string
	//go:embed jsonschemas/steps/syscalls/open.schema.json
	openSyscallStepSchema string
	//go:embed jsonschemas/steps/syscalls/openAt.schema.json
	openatSyscallStepSchema string
	//go:embed jsonschemas/steps/syscalls/openAt2.schema.json
	openat2SyscallStepSchema string
	//go:embed jsonschemas/steps/syscalls/read.schema.json
	readSyscallStepSchema string
	//go:embed jsonschemas/steps/syscalls/sendTo.schema.json
	sendtoSyscallStepSchema string
	//go:embed jsonschemas/steps/syscalls/socket.schema.json
	socketSyscallStepSchema string
	//go:embed jsonschemas/steps/syscalls/symLink.schema.json
	symlinkSyscallStepSchema string
	//go:embed jsonschemas/steps/syscalls/symLinkAt.schema.json
	symlinkatSyscallStepSchema string
	//go:embed jsonschemas/steps/syscalls/write.schema.json
	writeSyscallStepSchema string
	//go:embed jsonschemas/expectedOutcome.schema.json
	expectedOutcomeSchema string
)

// rootSchema is the identifier of the root schema.
var rootSchema = "description.schema.json"

// schemas associated to each schema identifier the corresponding schema.
var schemas = map[string]string{
	rootSchema:                              descriptionSchema,
	"binding.schema.json":                   bindingSchema,
	"test.schema.json":                      testSchema,
	"context.schema.json":                   contextSchema,
	"resource.schema.json":                  resourceSchema,
	"resources.clientServer.schema.json":    clientServerResourceSchema,
	"resources.fd.schema.json":              fdResourceSchema,
	"resources.fd.file.schema.json":         fileFDResourceSchema,
	"resources.fd.directory.schema.json":    directoryFDResourceSchema,
	"resources.fd.pipe.schema.json":         pipeFDResourceSchema,
	"resources.fd.event.schema.json":        eventFDResourceSchema,
	"resources.fd.signalfd.schema.json":     signalfdFDResourceSchema,
	"resources.fd.eventpoll.schema.json":    eventpollFDResourceSchema,
	"resources.fd.inotify.schema.json":      inotifyFDResourceSchema,
	"resources.fd.memfd.schema.json":        memfdFDResourceSchema,
	"resources.process.schema.json":         processResourceSchema,
	"step.schema.json":                      stepSchema,
	"steps.syscall.schema.json":             syscallStepSchema,
	"steps.syscall.connect.schema.json":     connectSyscallStepSchema,
	"steps.syscall.dup.schema.json":         dupSyscallStepSchema,
	"steps.syscall.dup2.schema.json":        dup2SyscallStepSchema,
	"steps.syscall.dup3.schema.json":        dup3SyscallStepSchema,
	"steps.syscall.finitModule.schema.json": finitModuleSyscallStepSchema,
	"steps.syscall.initModule.schema.json":  initModuleSyscallStepSchema,
	"steps.syscall.kill.schema.json":        killSyscallStepSchema,
	"steps.syscall.link.schema.json":        linkSyscallStepSchema,
	"steps.syscall.linkAt.schema.json":      linkatSyscallStepSchema,
	"steps.syscall.open.schema.json":        openSyscallStepSchema,
	"steps.syscall.openAt.schema.json":      openatSyscallStepSchema,
	"steps.syscall.openAt2.schema.json":     openat2SyscallStepSchema,
	"steps.syscall.read.schema.json":        readSyscallStepSchema,
	"steps.syscall.sendTo.schema.json":      sendtoSyscallStepSchema,
	"steps.syscall.socket.schema.json":      socketSyscallStepSchema,
	"steps.syscall.symLink.schema.json":     symlinkSyscallStepSchema,
	"steps.syscall.symLinkAt.schema.json":   symlinkatSyscallStepSchema,
	"steps.syscall.write.schema.json":       writeSyscallStepSchema,
	"expectedOutcome.schema.json":           expectedOutcomeSchema,
}

// Validate validates the provided object against the schema.
func Validate(obj any) error {
	schema, err := load()
	if err != nil {
		return fmt.Errorf("error loading schema: %w", err)
	}

	return schema.Validate(obj)
}

// load loads the schema.
func load() (*jsonschema.Schema, error) {
	compiler := jsonschema.NewCompiler()
	for key, schema := range schemas {
		doc, err := jsonschema.UnmarshalJSON(strings.NewReader(schema))
		if err != nil {
			return nil, fmt.Errorf("error unmarshaling sub-schema %v: %w", key, err)
		}

		if err := compiler.AddResource(key, doc); err != nil {
			return nil, fmt.Errorf("error adding schema resource %v: %w", key, err)
		}
	}

	schema, err := compiler.Compile(rootSchema)
	if err != nil {
		return nil, fmt.Errorf("error compiling: %w", err)
	}

	return schema, nil
}
