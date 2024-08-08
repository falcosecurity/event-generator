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

import "golang.org/x/sys/unix"

// Yaml file structure
type Args struct {
	// For open, openat, openat2 syscalls
	Dirfd    *int    `yaml:"dirfd,omitempty"`
	Filepath *string `yaml:"filepath,omitempty"`
	Flags    *int    `yaml:"flag,omitempty"`
	Mode     *uint32 `yaml:"mode,omitempty"`
	Resolve  *uint64 `yaml:"resolve,omitempty"`

	// For execve syscall
	Exepath *string   `yaml:"exepath,omitempty"`
	Cmnd    *[]string `yaml:"cmnd,omitempty"`
	Envv    *[]string `yaml:"envv,omitempty"`

	// For connect syscall
	Sockfd   *int           `yaml:"sockfd,omitempty"`
	Sockaddr *unix.Sockaddr `yaml:"sockaddr,omitempty"`

	// For socket syscall
	Domain   *int `yaml:"domain,omitempty"`
	SockType *int `yaml:"socktype,omitempty"`
	Protocol *int `yaml:"protocol,omitempty"`

	// For symlink and link syscalls
	Oldpath *string `yaml:"oldpath,omitempty"`
	Newpath *string `yaml:"newpath,omitempty"`

	// For dup syscall
	Oldfd *int `yaml:"oldfd,omitempty"`

	// For ptrace syscall
	Pid          *int `yaml:"pid,omitempty"`
	Ptracesignal *int `yaml:"ptracesignal,omitempty"`
}

type SyscallStep struct {
	Syscall string `yaml:"syscall"`
	Args    Args   `yaml:"args"`
}

type Test struct {
	Rule   string        `yaml:"rule"`
	Runner string        `yaml:"runner"`
	Before string        `yaml:"before"`
	Steps  []SyscallStep `yaml:"steps"`
	After  string        `yaml:"after"`
}

type Tests struct {
	Tests []Test `yaml:"tests"`
}
