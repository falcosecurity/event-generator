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

package events

var options = make(map[string]*actionOpts, 0)

type actionOpts struct {
	disabled bool
}

// Option is a functional option
type Option func(*actionOpts)

// Options is a slice of Option.
type Options []Option

func (o Options) applyTo(name string) {
	a, ok := options[name]
	if !ok {
		a = &actionOpts{}
		options[name] = a
	}
	for _, f := range o {
		f(a)
	}
}

func WithDisabled() Option {
	return func(a *actionOpts) {
		a.disabled = true
	}
}

func Disabled(name string) bool {
	if a, ok := options[name]; ok && a != nil {
		return a.disabled
	}
	return false
}
