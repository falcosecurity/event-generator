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

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func withTestOptionWithError() Option {
	return func(r *Runner) error {
		return errors.New("options error")
	}
}

func TestApply(t *testing.T) {

	r := &Runner{}
	testOptionCalled := false
	withTestOption := func() Option {
		return func(r *Runner) error {
			testOptionCalled = true
			assert.NotNil(t, r)
			return nil
		}
	}

	err := Options([]Option{
		withTestOption(),
	}).Apply(r)
	assert.NoError(t, err)
	assert.True(t, testOptionCalled)

	err = Options([]Option{
		withTestOptionWithError(),
	}).Apply(r)
	assert.Error(t, err)
}
