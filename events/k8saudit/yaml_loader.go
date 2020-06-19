package k8saudit

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/falcosecurity/event-generator/events"
	"github.com/falcosecurity/event-generator/events/k8saudit/yaml"
	"github.com/iancoleman/strcase"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/resource"
)

func init() {
	for n, b := range yaml.Bundle {

		// The filename must be in the dash-case format,
		// so it will be converted to CamelCase and used as action's name.
		fileName := n
		fileContent := b
		name := strcase.ToCamel(strings.TrimSuffix(fileName, filepath.Ext(fileName)))
		actionName := "k8saudit." + name

		opts := make(events.Options, 0)
		if disabled[fileName] {
			opts = append(opts, events.WithDisabled())
		}

		events.RegisterWithName(func(h events.Helper) error {
			count := 0
			r := h.ResourceBuilder().
				Unstructured().
				// Schema(schema). // todo(leogr): do we need this?
				ContinueOnError().
				Stream(bytes.NewReader(fileContent), fileName).
				Flatten().
				Do()
			if err := r.Err(); err != nil {
				return err
			}

			err := r.Visit(func(info *resource.Info, err error) error {
				if err != nil {
					return err
				}

				log := h.Log().
					WithField("kind", info.Mapping.GroupVersionKind.Kind).
					WithField("name", info.Name)

				h.Cleanup(func() {
					if _, err := resource.
						NewHelper(info.Client, info.Mapping).
						DeleteWithOptions(info.Namespace, info.Name, &metav1.DeleteOptions{}); err != nil {
						log.WithError(err).Error("delete k8s resource")
					}
				}, log)

				log.Info("create k8s resource")
				obj, err := resource.
					NewHelper(info.Client, info.Mapping).
					Create(info.Namespace, true, info.Object, nil)
				if err != nil {
					return err
				}
				info.Refresh(obj, true)

				count++
				return nil
			})
			if err != nil {
				return err
			}
			if count == 0 {
				return fmt.Errorf("no objects passed to create")
			}
			return nil
		},
			actionName,
			opts...,
		)
	}
}
