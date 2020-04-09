package events

import (
	logger "github.com/sirupsen/logrus"
	"k8s.io/cli-runtime/pkg/resource"
)

// A Helper is passed to an Action as argument.
type Helper interface {

	// Log returns an intermediate logger.Entry
	// that already contains default fields for the current action.
	Log() *logger.Entry

	// Cleanup registers a function to be called when the action complete or later.
	// Cleanup functions registered from within the same action will be called in last added,
	// first called order.
	Cleanup(f func(), args ...interface{})

	SpawnAs(name string, action string) error

	// ResourceBuilder returns a k8s' resource.Builder.
	ResourceBuilder() *resource.Builder
}

// An Action triggers an event.
type Action func(Helper) error
