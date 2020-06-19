package events

var options = make(map[string]*actionOpts, 0)

type actionOpts struct {
	disabled bool
}

// Option is a functional option
type Option func(*actionOpts)

// Options is a slice of Option.
type Options []Option

func (o Options) applyTo(name string) {
	a, ok := options[name]
	if !ok {
		a = &actionOpts{}
		options[name] = a
	}
	for _, f := range o {
		f(a)
	}
}

func WithDisabled() Option {
	return func(a *actionOpts) {
		a.disabled = true
	}
}

func Disabled(name string) bool {
	if a, ok := options[name]; ok && a != nil {
		return a.disabled
	}
	return false
}
