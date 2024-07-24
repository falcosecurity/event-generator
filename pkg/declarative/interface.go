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

import "context"

// Common runner interface for runners like hostrunner, container-runner etc..
type Runner interface {
	Setup(ctx context.Context, beforeScript string) error
	ExecuteStep(ctx context.Context, test Test) error
	Cleanup(ctx context.Context, afterScript string) error
}
