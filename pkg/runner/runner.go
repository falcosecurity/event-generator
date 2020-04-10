package runner

import (
	"os"
	"path/filepath"

	"github.com/falcosecurity/event-generator/events"
	logger "github.com/sirupsen/logrus"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
)

type Runner struct {
	log     *logger.Logger
	kf      cmdutil.Factory
	kn      string
	exePath string
	exeArgs []string
	alias   string
}

func (r *Runner) trigger(n string, f events.Action) (cleanup func(), err error) {
	fields := logger.Fields{
		"action": n,
	}
	if r.alias != "" {
		fields["as"] = r.alias
	}
	log := r.log.WithFields(fields)
	log.Info("trigger")

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

func WithExecutable(path string, args ...string) Option {
	return func(r *Runner) error {
		r.exePath = path
		r.exeArgs = args
		return nil
	}
}
