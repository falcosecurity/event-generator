package field

import (
	"fmt"
	"reflect"
	"strings"
)

type Retriever interface {
	// Field returns information related to the field with the provided name.
	Field(name string) (*Field, error)
}

// Field contains information regarding a field, such as its value and its field type.
type Field struct {
	Path  string
	Value reflect.Value
	Type  Type
}

// Type represents the type of field.
type Type string

const (
	TypeUndefined        Type = "undefined"
	TypeFD               Type = "fd"
	TypeBuffer           Type = "buffer"
	TypeBufferLen        Type = "buffer_len"
	TypeFilePath         Type = "file_path"
	TypeOpenFlags        Type = "open_flags"
	TypeOpenMode         Type = "open_mode"
	TypeOpenHow          Type = "open_how"
	TypeLinkAtFlags      Type = "linkat_flags"
	TypeModuleParams     Type = "module_params"
	TypeFinitModuleFlags Type = "finit_module_flags"
	TypeDup3Flags        Type = "dup3_flags"
	TypeSocketAddress    Type = "socket_address"
)

// Paths returns the field paths of the fields contained in the provided fieldContainer.
func Paths(fieldContainer reflect.Type) map[string]struct{} {
	fieldPaths := make(map[string]struct{}, fieldContainer.NumField())
	for i := 0; i < fieldContainer.NumField(); i++ {
		field := fieldContainer.Field(i)
		fieldTy := field.Type
		fieldPath := Path(field.Name)
		switch fieldTy.Kind() {
		case reflect.Ptr:
			fieldTy = fieldTy.Elem()
			if fieldTy.Kind() != reflect.Struct {
				fmt.Println(fieldTy)
				continue
			}
		case reflect.Struct:
		default:
			fieldPaths[fieldPath] = struct{}{}
			continue
		}
		subFieldPaths := Paths(fieldTy)
		for subFieldPath := range subFieldPaths {
			fieldPaths[fieldPath+"."+subFieldPath] = struct{}{}
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
	return strings.Split(fieldPath, ".")
}

// ByName returns information for the field identified by name and contained in one of the provided fieldContainers.
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
		Type:  fieldType(field),
	}
}

// fieldType returns the type of the provided struct field.
func fieldType(field reflect.StructField) Type {
	tagValue, ok := field.Tag.Lookup("field_type")
	if !ok || len(tagValue) == 0 {
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
