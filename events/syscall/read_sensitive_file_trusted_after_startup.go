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
	"github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(ReadSensitiveFileTrustedAfterStartup)

func ReadSensitiveFileTrustedAfterStartup(h events.Helper) error {
	// for the event to be triggered, the new process must run for at least 5 seconds
	return h.SpawnAsWithSymlink("httpd", "syscall.ReadSensitiveFileUntrusted", "--sleep", "6s")
}
