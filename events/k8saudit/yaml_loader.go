// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package k8saudit

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"

	"github.com/iancoleman/strcase"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/resource"

	"github.com/falcosecurity/event-generator/events"
	"github.com/falcosecurity/event-generator/events/k8saudit/yaml"
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
					Create(info.Namespace, true, info.Object)
				if err != nil {
					return err
				}

				if err := info.Refresh(obj, true); err != nil {
					log.WithError(err).Error("refresh k8s resource")
				}

				count++
				return nil
			})
			if err != nil {
				return err
			}
			if count == 0 {
				return errors.New("no objects passed to create")
			}
			return nil
		},
			actionName,
			opts...,
		)
	}
}
