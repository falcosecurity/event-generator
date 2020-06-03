package runner

import (
	"context"

	"github.com/falcosecurity/event-generator/events"
	logger "github.com/sirupsen/logrus"
)

type Plugin interface {
	PreRun(ctx context.Context, log *logger.Entry, n string, f events.Action) error
	PostRun(ctx context.Context, log *logger.Entry, n string, f events.Action) error
}
