package events

import (
	logger "github.com/sirupsen/logrus"
	"k8s.io/cli-runtime/pkg/resource"
)

type Helper interface {
	Log() *logger.Entry
	ResourceBuilder() *resource.Builder
}

type Action func(Helper) error
