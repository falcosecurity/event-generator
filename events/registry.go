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

import (
	"reflect"
	"regexp"
	"runtime"
	"strings"
)

var nonAlphaNumericReg = regexp.MustCompile("[^a-zA-Z0-9]+")

var registry = make(map[string]Action, 0)

// Register register an action.
func Register(f Action, opts ...Option) map[string]Action {
	n := getFuncName(f)
	checkName(n)
	return RegisterWithName(f, n, opts...)
}

// RegisterWithName registers an action with a given name.
func RegisterWithName(f Action, name string, opts ...Option) map[string]Action {
	checkName(name)
	registry[name] = f
	Options(opts).applyTo(name)
	return registry
}

func checkName(n string) {
	if n == "" { // todo(leogr): check name format too
		panic("event name cannot be empty")
	}
	if _, ok := registry[n]; ok {
		panic("event name already registered: " + n)
	}
}

func getFuncName(f interface{}) string {
	pc := reflect.ValueOf(f).Pointer()
	rf := runtime.FuncForPC(pc)
	parts := strings.Split(rf.Name(), "/")
	return parts[len(parts)-1]
}

// All returns a map of all registered actions
func All() map[string]Action {
	return registry
}

// ByRegexp returns a map of actions whose name matches the given regular expression.
func ByRegexp(r *regexp.Regexp) map[string]Action {
	ret := make(map[string]Action, 0)
	for n, f := range registry {
		if r.MatchString(n) {
			ret[n] = f
		}
	}
	return ret
}

// ByPackage returns a map of actions registered in given package.
func ByPackage(packageName string) map[string]Action {
	ret := make(map[string]Action, 0)
	for n, f := range registry {
		parts := strings.Split(n, ".")
		if len(parts) > 0 && parts[0] == packageName {
			ret[n] = f
		}
	}
	return ret
}

// MatchRule returns true if the name of an action matches a given rule.
func MatchRule(name string, rule string) bool {
	parts := strings.Split(name, ".")
	l := len(parts)
	if l == 0 {
		return false
	}

	return strings.ToLower(parts[l-1]) == strings.ToLower(nonAlphaNumericReg.ReplaceAllString(rule, ""))
}
