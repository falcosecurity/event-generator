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
	cleanup func()
}

func (h *helper) Log() *logger.Entry {
	return h.log
}

func (h *helper) ResourceBuilder() *resource.Builder {
	// todo(leogr): handle nil case
	return h.builder
}

// Cleanup registers a function to be called when the action complete or later.
// Cleanup functions registered from within the same action will be called in last added,
// first called order.
func (h *helper) Cleanup(f func(), args ...interface{}) {
	oldCleanup := h.cleanup
	h.cleanup = func() {
		if oldCleanup != nil {
			defer oldCleanup()
		}
		args = append([]interface{}{"clenaup "}, args...)
		h.Log().Info(args...)
		f()
	}
}

func (r *Runner) trigger(n string, f events.Action) (cleanup func(), err error) {
	fields := logger.Fields{
		"action": n,
	}
	log := r.log.WithFields(fields)
	log.Info("trigger")

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

	return h.cleanup, nil
}

func (r *Runner) Run(m map[string]events.Action) error {

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
