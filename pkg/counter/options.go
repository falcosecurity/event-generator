package counter

// Option is a functional option for extractors.
type Option func(*Counter) error

// Options is a slice of Option.
type Options []Option

// Apply interates over Options and calls each functional option with a given Counter.
func (o Options) Apply(c *Counter) error {
	for _, f := range o {
		if err := f(c); err != nil {
			return err
		}
	}

	return nil
}
