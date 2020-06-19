package tester

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/falcosecurity/client-go/pkg/api/outputs"
	"github.com/falcosecurity/client-go/pkg/client"
	"github.com/falcosecurity/event-generator/events"
	logger "github.com/sirupsen/logrus"
)

// ErrFailed is returned when a test fails
var ErrFailed = errors.New("test failed")

const DefaultTestTimeout = time.Minute

// Tester is a plugin that tests the action outcome in a running Falco instance via the gRCP API.
type Tester struct {
	outs    outputs.ServiceClient
	timeout time.Duration
}

// New returns a new Tester instance.
func New(config *client.Config, options ...Option) (*Tester, error) {
	c, err := client.NewForConfig(context.Background(), config)
	if err != nil {
		return nil, err
	}
	outs, err := c.Outputs()
	if err != nil {
		return nil, err
	}
	t := &Tester{
		outs:    outs,
		timeout: DefaultTestTimeout,
	}
	if err := Options(options).Apply(t); err != nil {
		return nil, err
	}
	return t, nil
}

func (t *Tester) PreRun(ctx context.Context, log *logger.Entry, n string, f events.Action) (err error) {
	return nil
}

func (t *Tester) PostRun(ctx context.Context, log *logger.Entry, n string, f events.Action, actErr error) error {

	if strings.HasPrefix(n, "helper.") {
		log.Info("test skipped for helpers")
		return nil
	}

	if actErr != nil {
		var skipErr *events.ErrSkipped
		if errors.As(actErr, &skipErr) {
			return nil // test skipped
		}
		return ErrFailed
	}

	ctxWithTimeout, cancelTimeout := context.WithTimeout(ctx, t.timeout)
	defer cancelTimeout()

	testCtx, cancel := context.WithCancel(ctxWithTimeout)
	defer cancel()

	fsc, err := t.outs.Sub(testCtx)
	if err != nil {
		return err
	}

	err = client.OutputsWatch(testCtx, fsc, func(res *outputs.Response) error {
		if events.MatchRule(n, res.Rule) {
			log.WithField("rule", res.Rule).WithField("source", res.Source).Info("test passed")
			cancel()
		} else {
			log.WithField("rule", res.Rule).WithField("source", res.Source).Debug("event skipped")
		}
		return nil
	}, time.Millisecond*100)

	if err == context.Canceled {
		return nil
	}
	if err != nil {
		return err
	}
	return ErrFailed
}

func WithTestTimeout(timeout time.Duration) Option {
	return func(t *Tester) error {
		t.timeout = timeout
		return nil
	}
}
