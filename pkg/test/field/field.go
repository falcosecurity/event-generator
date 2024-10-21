// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 The Falco Authors
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

package field

import (
	"fmt"
	"reflect"
	"strings"
)

// Retriever allows to retrieve information regarding fields.
type Retriever interface {
	// Field returns information related to the field with the provided name.
	Field(name string) (*Field, error)
}

// Field contains information regarding a field, such as its value and its field type.
type Field struct {
	// Path represents the unique location of a field in the parent container. A Path is composed of one or multiple
	// dot-separated field path segments. This addressing mechanism allows to organize fields in a hierarchical way.
	Path string
	// Value contains the value associated to the field. It can be settable or not, depending on how it is created.
	Value reflect.Value
	// Type is mainly used to check if a source Field Value can be semantically assigned to a destination Field Value.
	// Semantic assignability means that both fields have the same Type. A Type must be assigned to a Field via
	// `field_type` struct field tag (e.g.: `field_type:"<field_type>"`).
	Type Type
}

// Type represents the type of field.
type Type string

const (
	// TypeUndefined specifies an undefined field type. This is a special value indicating the absence of a Type for a
	// Field. The value of a Field marked as undefined cannot be assigned nor set to any other Field value.
	TypeUndefined Type = "undefined"
	// TypeFD specifies that the field contains a file descriptor.
	TypeFD Type = "fd"
	// TypeBuffer specifies that the field contains a buffer.
	TypeBuffer Type = "buffer"
	// TypeBufferLen specifies that the field contains a buffer length.
	TypeBufferLen Type = "buffer_len"
	// TypeFilePath specifies that the field contains a file path.
	TypeFilePath Type = "file_path"
	// TypeOpenFlags specifies that the field contains the open system call flags.
	TypeOpenFlags Type = "open_flags"
	// TypeOpenMode specifies that the field contains the open system call modes.
	TypeOpenMode Type = "open_mode"
	// TypeOpenHow specifies that the field contains the openat2 system call open_how parameter.
	TypeOpenHow Type = "open_how"
	// TypeLinkAtFlags specifies that the field contains the linkat system call flags.
	TypeLinkAtFlags Type = "linkat_flags"
	// TypeModuleParams specifies that the field contains the init_module system call params.
	TypeModuleParams Type = "module_params"
	// TypeFinitModuleFlags specifies that the field contains the finit_module system call flags.
	TypeFinitModuleFlags Type = "finit_module_flags"
	// TypeDup3Flags specifies that the field contains the dup3 system call flags.
	TypeDup3Flags Type = "dup3_flags"
	// TypeSocketAddress specifies that the field contains a sockaddr.
	TypeSocketAddress Type = "socket_address"
	// TypeSocketDomain specifies that the field contains the socket system call domain.
	TypeSocketDomain Type = "socket_domain"
	// TypeSocketType specifies that the field contains the socket system call type.
	TypeSocketType Type = "socket_type"
	// TypeSocketProtocol specifies that the field contains the socket system call protocol.
	TypeSocketProtocol Type = "socket_protocol"
	// TypeSendFlags specifies that the field contains the sendto system call flags.
	TypeSendFlags Type = "send_flags"
)

const (
	// fieldPathSegmentsSeparator is the token used to separate one segment from another in a multi-segment field path.
	fieldPathSegmentsSeparator = "."
)

// Paths returns the field paths of the fields contained in the provided fieldContainer. fieldContainer's Kind must be
// Struct; otherwise, the function will panic. A field path is generated for each field that is neither a struct nor a
// pointer to a struct. For each field whose type has the struct kind, the function recursively invokes itself to
// provide field paths for each of its eligible subfields. Each field that is a struct pointer is dereferenced and then
// treated as a field whose type has the struct kind.
func Paths(fieldContainer reflect.Type) map[string]struct{} {
	fieldContainerNumFields := fieldContainer.NumField()
	// Guess we are generating a number of path equal to the number of container fields.
	fieldPaths := make(map[string]struct{}, fieldContainerNumFields)
	for i := 0; i < fieldContainerNumFields; i++ {
		field := fieldContainer.Field(i)
		fieldTy := field.Type
		fieldPath := Path(field.Name)
		switch fieldTy.Kind() {
		case reflect.Ptr:
			// Dereference the pointer and give up if it does not point to a struct.
			fieldTy = fieldTy.Elem()
			if fieldTy.Kind() != reflect.Struct {
				continue
			}
		case reflect.Struct:
		default:
			// Field is neither a struct nor a pointer to a struct: add to the field paths set and go to the next field.
			fieldPaths[fieldPath] = struct{}{}
			continue
		}
		// At this point we know that the field type has the struct kind, so we can recursively call ourselves and
		// collect all subfields paths.
		subFieldPaths := Paths(fieldTy)
		// Generate the complete field path by prefixing, to each subfield, the current field path.
		for subFieldPath := range subFieldPaths {
			fieldPaths[fieldPath+fieldPathSegmentsSeparator+subFieldPath] = struct{}{}
		}
	}
	return fieldPaths
}

// Path converts the provided string to the corresponding field path representation.
func Path(s string) string {
	return strings.ToLower(s)
}

// splitFieldPath splits the provided field path into multiple segments.
func splitFieldPath(fieldPath string) []string {
	return strings.Split(fieldPath, fieldPathSegmentsSeparator)
}

// ByName returns information for the field identified by name. The field is searched in the provided fieldContainers,
// and the first match is returned.
func ByName(name string, fieldContainers ...reflect.Value) (*Field, error) {
	fieldPath := Path(name)
	fieldPathSegments := splitFieldPath(fieldPath)

	for _, fieldContainer := range fieldContainers {
		if field := byName(fieldContainer, fieldPath, fieldPathSegments); field != nil {
			return field, nil
		}
	}
	return nil, fmt.Errorf("unknown field %q", name)
}

// byName returns the fieldContainer's field identified by the provided fieldPathSegments. If a field is not found, it
// returns nil.
func byName(fieldContainer reflect.Value, fieldPath string, fieldPathSegments []string) *Field {
	for _, fieldPathSegment := range fieldPathSegments[:len(fieldPathSegments)-1] {
		field, ok := fieldContainer.Type().FieldByNameFunc(func(name string) bool {
			return Path(name) == fieldPathSegment
		})
		if !ok {
			return nil
		}
		fieldContainer = fieldContainer.FieldByIndex(field.Index)
	}

	lastFieldPathSegment := fieldPathSegments[len(fieldPathSegments)-1]
	field, ok := fieldContainer.Type().FieldByNameFunc(func(name string) bool {
		return Path(name) == lastFieldPathSegment
	})
	if !ok {
		return nil
	}

	return &Field{
		Path:  fieldPath,
		Value: fieldContainer.FieldByIndex(field.Index),
		Type:  fieldType(&field),
	}
}

// fieldType returns the type of the provided struct field.
func fieldType(field *reflect.StructField) Type {
	tagValue, ok := field.Tag.Lookup("field_type")
	if !ok || tagValue == "" {
		return TypeUndefined
	}
	return Type(tagValue)
}

// Set sets the Value of the current field to the Value of the provided source field. If the source Value is neither
// assignable nor convertible to the destination Value, or it is not semantically assignable to it, Set returns an
// error.
func (f *Field) Set(srcField *Field) error {
	dstFieldType := f.Type
	dstFieldValue := f.Value

	srcFieldType := srcField.Type
	srcFieldValue := srcField.Value

	if dstFieldType == TypeUndefined {
		return fmt.Errorf("field type is undefined for destination field")
	}

	if srcFieldType == TypeUndefined {
		return fmt.Errorf("field type is undefined for source field")
	}

	// Test raw type assignability or convertibility.
	isAssignable := srcFieldValue.Type().AssignableTo(dstFieldValue.Type())
	isConvertible := srcFieldValue.CanConvert(dstFieldValue.Type())
	if !isAssignable && !isConvertible {
		return fmt.Errorf("%T is neither assignable nor convertible to %T", srcFieldValue.Interface(),
			dstFieldValue.Interface())
	}

	// Test semantic type assignability
	if dstFieldType != srcFieldType {
		return fmt.Errorf("%q is not semantically assignable to %q", srcFieldType, dstFieldType)
	}

	if isAssignable {
		dstFieldValue.Set(srcFieldValue)
		return nil
	}

	// Not assignable but convertible
	dstFieldValue.Set(srcFieldValue.Convert(dstFieldValue.Type()))
	return nil
}
