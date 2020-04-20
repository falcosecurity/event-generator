package runner

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/falcosecurity/event-generator/events"
	logger "github.com/sirupsen/logrus"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
)

type Runner struct {
	ctx     context.Context
	log     *logger.Logger
	kf      cmdutil.Factory
	kn      string
	exePath string
	exeArgs []string
	alias   string
	sleep   time.Duration
	loop    bool
}

func (r *Runner) logEntry() *logger.Entry {
	l := r.log.WithContext(r.ctx)
	if r.alias != "" {
		l = l.WithField("as", r.alias)
	}
	return l
}

func (r *Runner) trigger(n string, f events.Action) (cleanup func(), err error) {
	fields := logger.Fields{
		"action": n,
	}
	log := r.logEntry().WithFields(fields)

	h := &helper{
		name:   n,
		runner: r,
		log:    log,
	}
	if r.kf != nil {
		h.builder = r.kf.NewBuilder().RequireNamespace()
		if r.kn != "" {
			h.builder.NamespaceParam(r.kn).DefaultNamespace()
		}
	}

	if r.sleep > 0 {
		h.Sleep(r.sleep)
	}

	if err := f(h); err != nil {
		log.WithError(err).Error("action error")
	} else if !h.hasLog {
		log.Info("action executed")
	}

	return h.cleanup, nil
}

func (r *Runner) runOnce(m map[string]events.Action) (err error, shutdown bool) {

	var cList []func()
	teardown := func() {
		for _, c := range cList {
			c()
		}
	}
	defer teardown()

	for n, f := range m {
		cleanup, err := r.trigger(n, f)
		if cleanup != nil {
			cList = append(cList, cleanup)
		}
		if err != nil {
			return err, false
		}
		select {
		case <-r.ctx.Done():
			return nil, true
		default:
			continue
		}
	}
	return nil, false
}

func (r *Runner) Run(m map[string]events.Action) (err error) {
	log := r.logEntry()
	var shutdown bool
	for err, shutdown = r.runOnce(m); r.loop && !shutdown; {
		log.Debug("restart loop")
		err, shutdown = r.runOnce(m)
	}
	if shutdown {
		log.Info("shutdown completed")
	}
	return
}

func procAlias() string {
	procPath, _ := os.Executable()
	procName := filepath.Base(procPath)
	calledAs := filepath.Base(os.Args[0])
	if procName != calledAs {
		return calledAs
	}
	return ""
}

func New(options ...Option) (*Runner, error) {
	r := &Runner{}

	if err := Options(options).Apply(r); err != nil {
		return nil, err
	}

	if r.ctx == nil {
		r.ctx = context.Background()
	}

	if r.log == nil {
		r.log = logger.New()
	}

	if r.exePath == "" {
		path, err := os.Executable()
		if err != nil {
			return nil, err
		}
		r.exePath = path
	}

	r.alias = procAlias()

	return r, nil
}

func WithContext(ctx context.Context) Option {
	return func(r *Runner) error {
		r.ctx = ctx
		return nil
	}
}

func WithLogger(l *logger.Logger) Option {
	return func(r *Runner) error {
		r.log = l
		return nil
	}
}

func WithSleep(d time.Duration) Option {
	return func(r *Runner) error {
		r.sleep = d
		return nil
	}
}

func WithLoop(loop bool) Option {
	return func(r *Runner) error {
		r.loop = loop
		return nil
	}
}

func WithKubeFactory(factory cmdutil.Factory) Option {
	return func(r *Runner) error {
		r.kf = factory
		return nil
	}
}

func WithKubeNamespace(namespace string) Option {
	return func(r *Runner) error {
		r.kn = namespace
		return nil
	}
}

func WithExecutable(path string, args ...string) Option {
	return func(r *Runner) error {
		r.exePath = path
		r.exeArgs = args
		return nil
	}
}
