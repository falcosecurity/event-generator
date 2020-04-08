package runner

import (
	"github.com/falcosecurity/event-generator/events"
	logger "github.com/sirupsen/logrus"
	"k8s.io/cli-runtime/pkg/resource"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
)

type Runner struct {
	log *logger.Logger
	kf  cmdutil.Factory
	kn  string
}

type helper struct {
	log     *logger.Entry
	builder *resource.Builder
}

func (h *helper) Log() *logger.Entry {
	return h.log
}

func (h *helper) ResourceBuilder() *resource.Builder {
	// todo(leogr): handle nil case
	return h.builder
}

func (r *Runner) Run(f events.Action, n string) (err error) {
	fields := logger.Fields{
		"action": n,
	}
	log := r.log.WithFields(fields)
	log.Info("running action")

	h := &helper{
		log: log,
	}
	if r.kf != nil {
		h.builder = r.kf.NewBuilder().RequireNamespace()
		if r.kn != "" {
			h.builder.NamespaceParam(r.kn).DefaultNamespace()
		}
	}

	if err := f(h); err != nil {
		log.WithError(err).Error("action error")
	}

	return nil
}

func (r *Runner) RunMany(m map[string]events.Action) error {
	for n, f := range m {
		if err := r.Run(f, n); err != nil {
			return err
		}
	}
	return nil
}

func New(options ...Option) (*Runner, error) {
	r := &Runner{}

	if err := Options(options).Apply(r); err != nil {
		return nil, err
	}

	if r.log == nil {
		r.log = logger.New()
	}

	return r, nil
}

func WithLogger(l *logger.Logger) Option {
	return func(r *Runner) error {
		r.log = l
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
