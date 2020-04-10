package events

import (
	"testing"

	evtPkg "github.com/falcosecurity/event-generator/events"
	"github.com/stretchr/testify/assert"

	// Register collections and run initialization
	// Duplicated name or init failure will be caught here
	_ "github.com/falcosecurity/event-generator/events/k8saudit"
	_ "github.com/falcosecurity/event-generator/events/syscall"
)

func TestEventPackages(t *testing.T) {
	assert.NotEmpty(t, evtPkg.All())
}
