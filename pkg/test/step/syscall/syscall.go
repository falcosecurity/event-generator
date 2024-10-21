package syscall

import (
	"github.com/falcosecurity/event-generator/pkg/test/step"
)

// Syscall defines a generic syscall test step.
type Syscall interface {
	step.Step
}

// Builder allows to build new syscall test steps.
type Builder interface {
	// Build builds a new Syscall based on the provided name and description.
	Build(name Name, stepName string, description *Description) (Syscall, error)
}

// Name is the static name of a syscall test step.
type Name string

const (
	NameWrite     = "write"
	NameRead      = "read"
	NameOpen      = "open"
	NameOpenAt    = "openat"
	NameOpenAt2   = "openat2"
	NameSymLink   = "symlink"
	NameSymLinkAt = "symlinkat"
	NameLink      = "link"
)

// Description contains information to build a new Syscall test step.
type Description struct {
	RawArgs       map[string]string
	FieldBindings []*step.FieldBinding
}
