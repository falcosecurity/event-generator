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

package runner

// Option is a functional option for extractors.
type Option func(*Runner) error

// Options is a slice of Option.
type Options []Option

// Apply interates over Options and calls each functional option with a given runner.
func (o Options) Apply(runner *Runner) error {
	for _, f := range o {
		if err := f(runner); err != nil {
			return err
		}
	}

	return nil
}
