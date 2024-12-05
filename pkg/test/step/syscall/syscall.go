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

package syscall

import (
	"github.com/falcosecurity/event-generator/pkg/test/step"
)

// Syscall defines a generic syscall test step.
type Syscall interface {
	step.Step
}

// Builder allows to build new syscall test steps.
type Builder interface {
	// Build builds a new Syscall based on the provided name and description.
	Build(name Name, stepName string, description *Description) (Syscall, error)
}

// Name is the static name of a syscall test step.
type Name string

const (
	// NameWrite specifies the name of the write system call test step.
	NameWrite = "write"
	// NameRead specifies the name of the read system call test step.
	NameRead = "read"
	// NameOpen specifies the name of the open system call test step.
	NameOpen = "open"
	// NameOpenAt specifies the name of the openat system call test step.
	NameOpenAt = "openat"
	// NameOpenAt2 specifies the name of the openat2 system call test step.
	NameOpenAt2 = "openat2"
	// NameSymLink specifies the name of the symlink system call test step.
	NameSymLink = "symlink"
	// NameSymLinkAt specifies the name of the symlinkat system call test step.
	NameSymLinkAt = "symlinkat"
	// NameLink specifies the name of the link system call test step.
	NameLink = "link"
	// NameLinkAt specifies the name of the linkat system call test step.
	NameLinkAt = "linkat"
	// NameInitModule specifies the name of the init_module system call test step.
	NameInitModule = "init_module"
	// NameFinitModule specifies the name of the finit_module system call test step.
	NameFinitModule = "finit_module"
	// NameDup specifies the name of the dup system call test step.
	NameDup = "dup"
	// NameDup2 specifies the name of the dup2 system call test step.
	NameDup2 = "dup2"
	// NameDup3 specifies the name of the dup2 system call test step.
	NameDup3 = "dup3"
	// NameConnect specifies the name of the connect system call test step.
	NameConnect = "connect"
	// NameSocket specifies the name of the socket system call test step.
	NameSocket = "socket"
	// NameSendTo specifies the name of the sendto system call test step.
	NameSendTo = "sendto"
	// NameKill specifies the name of the kill system call test step.
	NameKill = "kill"
)

// Description contains information to build a new Syscall test step.
type Description struct {
	RawArgs       map[string]any
	FieldBindings []*step.FieldBinding
}
