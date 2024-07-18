// Copyright 2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package encoding

import (
	"errors"
	"reflect"
)

const omitempty = "omitempty"

var errNoProfile = errors.New("could not identify profile field")

type embedded struct {
	Type  reflect.Type
	Value reflect.Value
}

// collectEmbedded returns true if the Field is embedded (regardless of
// whether or not it was collected).
func collectEmbedded(
	typeField *reflect.StructField,
	valField reflect.Value,
	embeds *[]embedded,
) bool {
	// embedded fields are always anonymous
	if !typeField.Anonymous {
		return false
	}

	if typeField.Name == typeField.Type.Name() &&
		(typeField.Type.Kind() == reflect.Struct ||
			typeField.Type.Kind() == reflect.Interface) {

		var fieldType reflect.Type
		var fieldValue reflect.Value

		if typeField.Type.Kind() == reflect.Interface {
			fieldValue = valField.Elem()
			if fieldValue.Kind() == reflect.Invalid {
				// no value underlying the interface
				return true
			}
			// use the interface's underlying value's real type
			fieldType = valField.Elem().Type()
		} else {
			fieldType = typeField.Type
			fieldValue = valField
		}

		*embeds = append(*embeds, embedded{Type: fieldType, Value: fieldValue})
		return true
	}

	return false
}
