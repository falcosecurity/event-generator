package tester

// Option is a functional option for extractors.
type Option func(*Tester) error

// Options is a slice of Option.
type Options []Option

// Apply interates over Options and calls each functional option with a given tester.
func (o Options) Apply(t *Tester) error {
	for _, f := range o {
		if err := f(t); err != nil {
			return err
		}
	}

	return nil
}
