package runner

// Option is a functional option for extractors.
type Option func(*Runner) error

// Options is a slice of Option.
type Options []Option

// Apply interates over Options and calls each functional option with a given runner.
func (o Options) Apply(runner *Runner) error {
	for _, f := range o {
		if err := f(runner); err != nil {
			return err
		}
	}

	return nil
}
