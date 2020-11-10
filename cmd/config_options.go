package cmd

import (
	"fmt"

	"github.com/creasty/defaults"
	"github.com/falcosecurity/event-generator/cmd/internal/validate"
	"github.com/go-playground/validator/v10"
	logger "github.com/sirupsen/logrus"
)

// ConfigOptions represent the persistent configuration flags of event-generator.
type ConfigOptions struct {
	ConfigFile string
	LogLevel   string `validate:"logrus" name:"log level" default:"info"`
	LogFormat  string `validate:"format" name:"log format" default:"text"`
}

// NewConfigOptions creates an instance of ConfigOptions.
func NewConfigOptions() *ConfigOptions {
	o := &ConfigOptions{}
	if err := defaults.Set(o); err != nil {
		logger.WithError(err).WithField("options", "ConfigOptions").Fatal("error setting event-generator options defaults")
	}
	return o
}

// Validate validates the ConfigOptions fields.
func (co *ConfigOptions) Validate() []error {
	if err := validate.V.Struct(co); err != nil {
		errors := err.(validator.ValidationErrors)
		errArr := []error{}
		for _, e := range errors {
			// Translate each error one at a time
			errArr = append(errArr, fmt.Errorf(e.Translate(validate.T)))
		}
		return errArr
	}
	return nil
}
