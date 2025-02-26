// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 The Falco Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package explain

import (
	"fmt"
	"io"
	"reflect"
	"strings"

	"github.com/goccy/go-yaml"

	"github.com/falcosecurity/event-generator/pkg/test/loader/schema"
)

// documentationEncoder allows to encode the documentation.
type documentationEncoder interface {
	// encode encodes the node tree starting at the provided node with a specific format and writes it to the underlying
	// destination.
	encode(node *schema.Node) error
}

// textEncoder encodes a node tree using a custom text-based format.
// Notice: the format slightly variates from YAML, as it uses capitalized snake-cased key, adaptive list printing and
// additional spacing.
type textEncoder struct {
	w io.Writer
}

// Verify that textEncoder implements documentationEncoder interface.
var _ documentationEncoder = (*textEncoder)(nil)

// newTextEncoder creates a new textEncoder able to write the node tree to the provided destination.
func newTextEncoder(w io.Writer) *textEncoder {
	return &textEncoder{w: w}
}

// encode encodes the provided node tree and writes it to the underlying destination.
func (e *textEncoder) encode(node *schema.Node) error {
	if node == nil {
		return nil
	}

	sb := &strings.Builder{}
	writeNode(sb, "", node)
	_, err := fmt.Fprint(e.w, sb.String())
	return err
}

const defaultPadding = "   "

// writeNode writes the node hierarchy starting at the providing node to the provided string builder.
func writeNode(sb *strings.Builder, padding string, node *schema.Node) {
	if node == nil {
		return
	}

	writeKeyValue(sb, padding, "NAME", node.Name)
	writeKeySlice(sb, padding, "DESCRIPTIONS", node.Descriptions)
	writeKeySliceInline(sb, padding, "TYPES", node.JSONTypes)
	writeKeyValue(sb, padding, "REQUIRED", node.Required)
	writeKeyValue(sb, padding, "MINIMUM", node.Minimum)
	writeKeyValue(sb, padding, "MIN_LENGTH", node.MinLength)
	writeKeyValue(sb, padding, "MIN_ITEMS", node.MinItems)
	writeKeyValue(sb, padding, "MIN_PROPERTIES", node.MinProperties)
	writeKeyValue(sb, padding, "PATTERN", node.Pattern)
	writeKeySliceInline(sb, padding, "ENUM", node.Enum)
	writeKeyValue(sb, padding, "DEFAULT", node.Default)
	writeKeySlice(sb, padding, "EXAMPLES", node.Examples)

	if metadata := node.Metadata; metadata != nil {
		writeKeyValue(sb, padding, "FIELD_TYPE", metadata.Type)
		writeKeyValue(sb, padding, "IS_BIND_ONLY", metadata.IsBindOnly)
	}

	length := len(node.Children)
	if length > 0 {
		writeFormatted(sb, "%sFIELDS:\n", padding)
	}
	for idx, child := range node.Children {
		writeNode(sb, padding+defaultPadding, child)
		if idx != length-1 {
			sb.WriteByte('\n')
		}
	}

	length = len(node.PseudoChildren)
	if length > 0 {
		writeFormatted(sb, "%sEXPOSED FIELDS:\n", padding)
	}
	for idx, child := range node.PseudoChildren {
		writeNode(sb, padding+defaultPadding, child)
		if idx != length-1 {
			sb.WriteByte('\n')
		}
	}
}

// writeKeyValue writes the association between the provided key and the value to the provided string builder. If the
// provided value is a nil pointer, is the zero value of its kind, or it is a pointer pointing to a zero value, nothing
// is written.
func writeKeyValue(sb *strings.Builder, padding, key string, value any) {
	valueOfValue := reflect.ValueOf(value)

	// Don't write anything if it is the zero value for its type.
	if valueOfValue.IsZero() {
		return
	}

	// If it is a pointer, dereference it.
	valueOfValue = reflect.Indirect(valueOfValue)

	// Check if the dereferenced value is the zero value for its type.
	if valueOfValue.IsZero() {
		return
	}

	writeFormatted(sb, "%s%s: %v\n", padding, key, valueOfValue.Interface())
}

// writeFormatted is a wrapper around fmt.Fprintf ignoring the returned values.
func writeFormatted(w io.Writer, format string, a ...any) {
	_, _ = fmt.Fprintf(w, format, a...)
}

// writeKeySlice writes, if the provided slice is not empty, the association between the provided key and the slice to
// the provided string builder. The output format depends on the number of elements the slice contains.
func writeKeySlice[T any](sb *strings.Builder, padding, key string, slice []T) {
	if len(slice) == 0 {
		return
	}

	writeFormatted(sb, "%s%s", padding, key)
	switch len(slice) {
	case 1:
		writeFormatted(sb, ": %v\n", slice[0])
	default:
		writeFormatted(sb, ":\n")
		for _, e := range slice {
			writeFormatted(sb, "%s- %v\n", padding+defaultPadding, e)
		}
	}
}

// writeKeySliceInline is a variant of writeKeySlice writing multiple slice elements as a comma-separated list.
func writeKeySliceInline[T any](sb *strings.Builder, padding, key string, slice []T) {
	if len(slice) == 0 {
		return
	}

	writeFormatted(sb, "%s%s", padding, key)
	switch len(slice) {
	case 1:
		writeFormatted(sb, ": %v", slice[0])
	default:
		writeFormatted(sb, ": %v", slice[0])
		for _, e := range slice[1:] {
			writeFormatted(sb, ", %v", e)
		}
	}
	sb.WriteByte('\n')
}

// yamlEncoder encodes a node tree using a YAML format.
type yamlEncoder struct {
	w io.Writer
}

// Verify that yamlEncoder implements documentationEncoder interface.
var _ documentationEncoder = (*yamlEncoder)(nil)

// newYAMLEncoder creates a new yamlEncoder able to write the node tree to the provided destination.
func newYAMLEncoder(w io.Writer) *yamlEncoder {
	return &yamlEncoder{w: w}
}

func (e *yamlEncoder) encode(node *schema.Node) error {
	return yaml.NewEncoder(e.w).Encode(node)
}
