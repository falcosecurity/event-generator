package counter

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/falcosecurity/client-go/pkg/api/outputs"
	"github.com/falcosecurity/client-go/pkg/client"
	"github.com/falcosecurity/event-generator/events"
	"github.com/prometheus/procfs"
	logger "github.com/sirupsen/logrus"
)

type stat struct {
	expected uint64
	actual   uint64
}

// Counter is a plugin that
type Counter struct {
	log     *logger.Logger
	ticker  *time.Ticker
	tickD   time.Duration
	lastT   time.Time
	outs    outputs.ServiceClient
	proc    *procfs.Proc
	lastS   *procfs.ProcStat
	actions []string
	list    map[string]*stat
}

// New returns a new Counter instance.
func New(ctx context.Context, config *client.Config, options ...Option) (*Counter, error) {
	c, err := client.NewForConfig(ctx, config)
	if err != nil {
		return nil, err
	}
	outs, err := c.Outputs()
	if err != nil {
		return nil, err
	}
	cntr := &Counter{
		outs: outs,
	}
	if err := Options(options).Apply(cntr); err != nil {
		return nil, err
	}

	if cntr.log == nil {
		cntr.log = logger.New()
	}

	cntr.list = make(map[string]*stat, len(cntr.actions))
	for _, n := range cntr.actions {
		cntr.list[n] = &stat{}
	}

	fsc, err := cntr.outs.Sub(ctx)
	if err != nil {
		return nil, err
	}

	go cntr.watcher(ctx, fsc)
	if cntr.tickD > 0 {
		go cntr.clock(ctx, cntr.tickD)
	}

	return cntr, nil
}

func (c *Counter) watcher(ctx context.Context, fsc outputs.Service_SubClient) {
	err := client.OutputsWatch(ctx, fsc, func(res *outputs.Response) error {
		for n := range c.list {
			if events.MatchRule(n, res.Rule) {
				s := c.list[n]
				atomic.AddUint64(&s.actual, 1)
				break
			}
		}
		return nil
	}, time.Millisecond*500)
	if err != nil {
		c.log.WithError(err).Error("gRPC error")
	}
}

func (c *Counter) clock(ctx context.Context, d time.Duration) {
	c.ticker = time.NewTicker(d)
	c.lastT = time.Now()
	for {
		select {
		case t := <-c.ticker.C:
			c.logStats()
			c.lastT = t
		case <-ctx.Done():
			c.ticker.Stop()
			c.logStats()
			return
		}
	}
}

func (c *Counter) statsByAction(n string) (expected, actual uint64) {
	if s, ok := c.list[n]; ok {
		return atomic.LoadUint64(&s.expected), atomic.LoadUint64(&s.actual)
	}
	return 0, 0
}

func (c *Counter) PreRun(ctx context.Context, log *logger.Entry, n string, f events.Action) (err error) {
	return nil
}

func (c *Counter) PostRun(ctx context.Context, log *logger.Entry, n string, f events.Action, actErr error) error {
	if s, ok := c.list[n]; ok {
		atomic.AddUint64(&s.expected, 1)
	}
	return nil
}

func WithLogger(l *logger.Logger) Option {
	return func(c *Counter) error {
		c.log = l
		return nil
	}
}

func WithActions(actions map[string]events.Action) Option {
	return func(c *Counter) error {
		c.actions = make([]string, len(actions))
		i := 0
		for n := range actions {
			c.actions[i] = n
			i++
		}
		return nil
	}
}

func WithStatsInterval(interval time.Duration) Option {
	return func(c *Counter) error {
		c.tickD = interval
		return nil
	}
}

func WithPid(pid int) Option {
	return func(c *Counter) error {
		proc, err := procfs.NewProc(pid)
		if err != nil {
			return err
		}
		c.proc = &proc
		procStat, err := c.proc.NewStat()
		if err != nil {
			return err
		}
		c.lastS = &procStat
		return nil
	}
}
