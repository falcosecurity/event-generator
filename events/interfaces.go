package events

import (
	"time"

	logger "github.com/sirupsen/logrus"
	"k8s.io/cli-runtime/pkg/resource"
)

// A Helper is passed to an Action as argument.
type Helper interface {

	// Log returns an intermediate logger.Entry
	// that already contains default fields for the current action.
	Log() *logger.Entry

	// Sleep pauses the current goroutine for at least the given duration and logs that.
	Sleep(time.Duration)

	// Cleanup registers a function to be called when the action complete or later.
	// Cleanup functions registered from within the same action will be called in last added,
	// first called order.
	Cleanup(f func(), args ...interface{})

	// SpawnAs respawns the process as name and run another action.
	// An action must not spawn itself to avoid an infinite loop.
	SpawnAs(name string, action string, args ...string) error

	// ResourceBuilder returns a k8s' resource.Builder.
	ResourceBuilder() *resource.Builder
}

// An Action triggers an event.
type Action func(Helper) error
