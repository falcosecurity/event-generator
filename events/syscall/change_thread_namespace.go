//go:build linux
// +build linux

// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.
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

package syscall

import (
	"golang.org/x/sys/unix"

	"github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(
	ChangeThreadNamespace,
	events.WithDisabled(), // the rule is not enabled by default, so disable the action too
)

func ChangeThreadNamespace(h events.Helper) error {
	// It doesn't matter that the arguments to Setns are
	// bogus. It's the attempt to call it that will trigger the
	// rule.
	h.Log().Debug("does not result in a falco notification in containers, unless container run with --privileged or --security-opt seccomp=unconfined")
	unix.Setns(0, 0)
	return nil
}
