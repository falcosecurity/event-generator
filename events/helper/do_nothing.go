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

package helper

import (
	"github.com/falcosecurity/event-generator/events"
)

var _ = events.Register(DoNothing)

// DoNothing does nothing.
// It can be used to just test execve events or command line arguments
// when using the helper function SpawnAs.
func DoNothing(h events.Helper) error {
	h.Log().Info("DoNothing helper")
	return nil
}
