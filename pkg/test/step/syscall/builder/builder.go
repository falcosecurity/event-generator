package builder

import (
	"fmt"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/connect"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/dup"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/dup2"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/dup3"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/finitmodule"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/initmodule"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/link"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/linkat"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/open"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/openat"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/openat2"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/read"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/sendto"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/socket"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/symlink"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/symlinkat"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/write"
)

// builder is an implementation of syscall.Builder.
type builder struct{}

// Verify that builder implements syscall.Syscall interface.
var _ syscall.Builder = (*builder)(nil)

// New creates a new builder.
func New() syscall.Builder {
	return &builder{}
}

func (b *builder) Build(name syscall.Name, stepName string, description *syscall.Description) (syscall.Syscall, error) {
	rawArgs := description.RawArgs
	fieldBindings := description.FieldBindings
	switch name {
	case syscall.NameWrite:
		return write.New(stepName, rawArgs, fieldBindings)
	case syscall.NameRead:
		return read.New(stepName, rawArgs, fieldBindings)
	case syscall.NameDup:
		return dup.New(stepName, rawArgs, fieldBindings)
	case syscall.NameDup2:
		return dup2.New(stepName, rawArgs, fieldBindings)
	case syscall.NameDup3:
		return dup3.New(stepName, rawArgs, fieldBindings)
	case syscall.NameConnect:
		return connect.New(stepName, rawArgs, fieldBindings)
	case syscall.NameSocket:
		return socket.New(stepName, rawArgs, fieldBindings)
	case syscall.NameOpen:
		return open.New(stepName, rawArgs, fieldBindings)
	case syscall.NameOpenAt:
		return openat.New(stepName, rawArgs, fieldBindings)
	case syscall.NameOpenAt2:
		return openat2.New(stepName, rawArgs, fieldBindings)
	case syscall.NameLink:
		return link.New(stepName, rawArgs, fieldBindings)
	case syscall.NameLinkAt:
		return linkat.New(stepName, rawArgs, fieldBindings)
	case syscall.NameSymLink:
		return symlink.New(stepName, rawArgs, fieldBindings)
	case syscall.NameSymLinkAt:
		return symlinkat.New(stepName, rawArgs, fieldBindings)
	case syscall.NameInitModule:
		return initmodule.New(stepName, rawArgs, fieldBindings)
	case syscall.NameFinitModule:
		return finitmodule.New(stepName, rawArgs, fieldBindings)
	case syscall.NameSendTo:
		return sendto.New(stepName, rawArgs, fieldBindings)
	default:
		return nil, fmt.Errorf("unknown syscall %q", name)
	}
}
