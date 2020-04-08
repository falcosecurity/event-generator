package k8saudit

import (
	"bytes"
	"fmt"

	"github.com/falcosecurity/event-generator/events"
	"github.com/falcosecurity/event-generator/events/k8saudit/yaml"
	"k8s.io/cli-runtime/pkg/resource"
)

func init() {
	for name, b := range yaml.Bundle {
		count := 0
		events.RegisterWithName(func(h events.Helper) error {
			r := h.ResourceBuilder().
				Unstructured().
				// Schema(schema).
				// ContinueOnError().

				// NamespaceParam(cmdNamespace).DefaultNamespace().
				// FilenameParam(enforceNamespace, &o.FilenameOptions).
				// LabelSelectorParam(o.Selector).
				Stream(bytes.NewReader(b), name).
				Flatten().
				Do()
			if err := r.Err(); err != nil {
				return err
			}

			err := r.Visit(func(info *resource.Info, err error) error {
				if err != nil {
					return err
				}
				// if err := util.CreateOrUpdateAnnotation(cmdutil.GetFlagBool(cmd, cmdutil.ApplyAnnotationsFlag), info.Object, scheme.DefaultJSONEncoder()); err != nil {
				// 	return cmdutil.AddSourceToErr("creating", info.Source, err)
				// }

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
