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
