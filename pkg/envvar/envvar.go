// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The Falco Authors
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

package envvar

import (
	"fmt"
	"strings"
)

// KeyFromFlagName converts the provided flag name into the corresponding environment variable key.
func KeyFromFlagName(envKeysPrefix, flagName string) string {
	s := fmt.Sprintf("%s_%s", envKeysPrefix, strings.ToUpper(flagName))
	s = strings.ToUpper(s)
	return strings.ReplaceAll(s, "-", "_")
}

// EnvVar creates an environment variable string in the form "<key>=<value>".
func EnvVar(key, value string) string {
	return fmt.Sprintf("%s=%s", key, value)
}

// KeyAndVal returns the key and the value of the provided environment variable. The extraction is performed by
// splitting at the first "=" sign. The boolean indicates if the extraction succeeded or failed (this can happen in case
// of malformed input).
func KeyAndVal(envVar string) (key, value string, success bool) {
	key, value, success = strings.Cut(envVar, "=")
	return
}
