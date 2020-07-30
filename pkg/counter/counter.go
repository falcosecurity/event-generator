package counter

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/falcosecurity/client-go/pkg/api/outputs"
	"github.com/falcosecurity/client-go/pkg/client"
	"github.com/falcosecurity/event-generator/events"
	"github.com/prometheus/procfs"
	logger "github.com/sirupsen/logrus"
)

type stat struct {
	actual   uint64
	expected uint64
}

// Counter is a plugin that
type Counter struct {
	i        uint64
	sleep    int64
	loop     bool
	log      *logger.Logger
	ticker   *time.Ticker
	tickD    time.Duration
	lastT    time.Time
	outs     outputs.ServiceClient
	pTimeout time.Duration
	proc     *procfs.Proc
	lastS    *procfs.ProcStat
	actions  []string
	list     map[string]*stat
	sync.RWMutex
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

	fcs, err := cntr.outs.Sub(ctx)
	if err != nil {
		return nil, err
	}

	go cntr.watcher(ctx, fcs)

	if cntr.tickD > 0 {
		go cntr.clock(ctx, cntr.tickD)
	}

	return cntr, nil
}

func (c *Counter) watcher(ctx context.Context, fcs outputs.Service_SubClient) {
	err := client.OutputsWatch(ctx, fcs, func(res *outputs.Response) error {
		for n := range c.list {
			if events.MatchRule(n, res.Rule) {
				s := c.list[n]
				atomic.AddUint64(&s.actual, 1)
				break
			}
		}
		return nil
	}, c.pTimeout)
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
			c.Lock()
			c.logStats()
			c.reset(t)
			c.Unlock()
		case <-ctx.Done():
			c.Lock()
			defer c.Unlock()
			c.ticker.Stop()
			c.logStats()
			return
		}
	}
}

func (c *Counter) reset(t time.Time) {
	c.lastT = t
	c.i = 0

	dirty := false
	for _, s := range c.list {
		dirty = dirty || atomic.LoadUint64(&s.actual) > atomic.LoadUint64(&s.expected)
		atomic.StoreUint64(&s.expected, 0)
		atomic.StoreUint64(&s.actual, 0)
	}

	if dirty {
		c.log.Warnf("unexpected events received, retrying with sleep=%s", time.Duration(c.sleep).String())
	}

	if c.loop && !dirty && c.sleep > 0 {
		c.sleep = c.sleep / 2
	}
}

func (c *Counter) PreRun(ctx context.Context, log *logger.Entry, n string, f events.Action) (err error) {
	c.Lock()
	c.i++
	sleep := c.sleep
	c.Unlock()

	if sleep > 0 {
		time.Sleep(time.Duration(sleep))
	}
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

func WithLoop(loop bool) Option {
	return func(c *Counter) error {
		c.loop = loop
		return nil
	}
}

func WithInitialSleep(sleep time.Duration) Option {
	return func(c *Counter) error {
		c.sleep = int64(sleep)
		return nil
	}
}

func WithStatsInterval(interval time.Duration) Option {
	return func(c *Counter) error {
		c.tickD = interval
		return nil
	}
}

func WithPollingTimeout(timeout time.Duration) Option {
	return func(c *Counter) error {
		c.pTimeout = timeout
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
