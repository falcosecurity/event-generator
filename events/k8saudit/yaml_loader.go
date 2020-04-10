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
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/cli-runtime/pkg/resource"
)

func init() {
	for n, b := range yaml.Bundle {
		fileName := n
		// todo(leogr): use labels
		name := strcase.ToCamel(strings.TrimSuffix(fileName, filepath.Ext(fileName)))
		reader := bytes.NewReader(b)
		events.RegisterWithName(func(h events.Helper) error {
			count := 0
			// uidMap := cmdwait.UIDMap{}
			// infos := []*resource.Info{}
			r := h.ResourceBuilder().
				Unstructured().
				// Schema(schema).
				ContinueOnError().
				Stream(reader, fileName).
				Flatten().
				Do()
			if err := r.Err(); err != nil {
				return err
			}

			err := r.Visit(func(info *resource.Info, err error) error {
				if err != nil {
					return err
				}

				log := h.Log().WithField("resource", info.Name)

				h.Cleanup(func() {
					if _, err := resource.
						NewHelper(info.Client, info.Mapping).
						DeleteWithOptions(info.Namespace, info.Name, &metav1.DeleteOptions{}); err != nil {
						log.WithError(err).Error("delete k8s resource")
					}
				}, log)

				if uo, ok := info.Object.(*unstructured.Unstructured); ok {
					labels := uo.GetLabels()
					if rule, ok := labels["falco.org/rule"]; ok {
						log = log.WithField("rule", rule)
					}
				}

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
			"k8saudit."+name,
		)
	}
}
