package tester

import (
	"context"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/falcosecurity/client-go/pkg/api/outputs"
	"github.com/falcosecurity/client-go/pkg/client"
	"github.com/falcosecurity/event-generator/events"
	logger "github.com/sirupsen/logrus"
)

// ErrFailed is returned when a test fails
var ErrFailed = errors.New("test failed")

// Tester is a plugin that tests the action outcome in a running Falco instance via the gRCP API.
type Tester struct {
	outs outputs.ServiceClient
	sgc  outputs.Service_GetClient
}

// New returns a new Tester instance.
func New(config *client.Config) (*Tester, error) {
	c, err := client.NewForConfig(context.Background(), config)
	if err != nil {
		return nil, err
	}
	outs, err := c.Outputs()
	if err != nil {
		return nil, err
	}
	return &Tester{
		outs: outs,
	}, nil
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

	// fixme(leogr): it ensures that the gRPC server has enough time to internally fetch events
	time.Sleep(time.Second)

	var err error
	t.sgc, err = t.outs.Get(ctx, &outputs.Request{})
	if err != nil {
		return err
	}

	// Receive the accumulated events
	for {
		res, err := t.sgc.Recv()
		if err != nil {
			if err == io.EOF {
				return ErrFailed
			}
			return err
		}

		if events.MatchRule(n, res.Rule) {
			log.WithField("rule", res.Rule).WithField("source", res.Source).Info("test passed")
			return nil
		}
		log.WithField("rule", res.Rule).WithField("source", res.Source).Debug("event skipped")
	}
}
