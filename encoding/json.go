// Copyright 2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package encoding

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
)

// SerializeStructToJSON serializes the provided struct to JSON. The behavior
// is broadly equivalent to calling json.Marashal(source), with the exception
// that embedded structs will be "merged" with their parents, so that the
// fields of the embedded struct will be treated as the fields of the parent
// when marshaling.
func SerializeStructToJSON(source any) ([]byte, error) {
	rawMap := newStructFieldsJSON()

	structType := reflect.TypeOf(source)
	structVal := reflect.ValueOf(source)

	if err := doSerializeStructToJSON(rawMap, structType, structVal); err != nil {
		return nil, err
	}

	return rawMap.ToJSON()
}

// PopulateStructFromJSON deserializes provided data into dest (must be a
// pointer to a struct).The behavior is broadly equivalent to calling
// json.Unmarshal(data), with the exception that embedded structs' fields will
// be  treated as their parents' fields (rather than the default behavior of
// treating the embedded struct as a single field of its parent).
func PopulateStructFromJSON(data []byte, dest any) error {
	rawMap := newStructFieldsJSON()

	if err := rawMap.FromJSON(data); err != nil {
		return err
	}

	structType := reflect.TypeOf(dest)
	structVal := reflect.ValueOf(dest)

	return doPopulateStructFromJSON(rawMap, structType, structVal)
}

// GetProfileJSONTag returns the JSON tag associated with the profile field.
// The field is identified by the corresponding CBOR tag, or, if an appropriate
// CBOR tag is not found, by the field name.
func GetProfileJSONTag(iface interface{}) (string, error) {
	structType := reflect.TypeOf(iface)
	structVal := reflect.ValueOf(iface)

	if structType.Kind() == reflect.Pointer {
		structType = structType.Elem()
		structVal = structVal.Elem()
	}

	return doGetProfileJSONTag(structType, structVal)
}

func doSerializeStructToJSON(
	rawMap *structFieldsJSON,
	structType reflect.Type,
	structVal reflect.Value,
) error {
	if structType.Kind() == reflect.Pointer {
		structType = structType.Elem()
		structVal = structVal.Elem()
	}

	var embeds []embedded

	for i := 0; i < structVal.NumField(); i++ {
		typeField := structType.Field(i)
		valField := structVal.Field(i)

		if collectEmbedded(&typeField, valField, &embeds) {
			continue
		}

		tag, ok := typeField.Tag.Lookup("json")
		if !ok {
			continue
		}

		parts := strings.Split(tag, ",")
		key := parts[0]

		if key == "-" {
			continue // field is not marshaled
		}

		isOmitEmpty := false
		if len(parts) > 1 {
			for _, option := range parts[1:] {
				if option == omitempty {
					isOmitEmpty = true
					break
				}
			}
		}

		// do not serialize zero values if the corresponding field is
		// omitempty
		if isOmitEmpty && valField.IsZero() {
			continue
		}

		data, err := json.Marshal(valField.Interface())
		if err != nil {
			return fmt.Errorf("error marshaling field %q: %w",
				typeField.Name,
				err,
			)
		}

		if err := rawMap.Add(key, json.RawMessage(data)); err != nil {
			return err
		}
	}

	for _, emb := range embeds {
		if err := doSerializeStructToJSON(rawMap, emb.Type, emb.Value); err != nil {
			return err
		}
	}

	return nil
}

func doPopulateStructFromJSON(
	rawMap *structFieldsJSON,
	structType reflect.Type,
	structVal reflect.Value,
) error {
	if structType.Kind() == reflect.Pointer {
		structType = structType.Elem()
		structVal = structVal.Elem()
	}

	var embeds []embedded

	for i := 0; i < structVal.NumField(); i++ {
		typeField := structType.Field(i)
		valField := structVal.Field(i)

		if collectEmbedded(&typeField, valField, &embeds) {
			continue
		}

		tag, ok := typeField.Tag.Lookup("json")
		if !ok {
			continue
		}

		parts := strings.Split(tag, ",")
		key := parts[0]

		if key == "-" {
			continue // field is not marshaled
		}

		isOmitEmpty := false
		if len(parts) > 1 {
			for _, option := range parts[1:] {
				if option == omitempty {
					isOmitEmpty = true
					break
				}
			}
		}

		rawVal, ok := rawMap.Get(key)
		if !ok {
			if isOmitEmpty {
				continue
			}

			return fmt.Errorf("missing mandatory field %q (%q)",
				typeField.Name, key)
		}

		fieldPtr := valField.Addr().Interface()
		if err := json.Unmarshal(rawVal, fieldPtr); err != nil {
			return fmt.Errorf("error unmarshaling field %q: %w",
				typeField.Name,
				err,
			)
		}

		rawMap.Delete(key)
	}

	for _, emb := range embeds {
		if err := doPopulateStructFromJSON(rawMap, emb.Type, emb.Value); err != nil {
			return err
		}
	}

	return nil
}

// structFieldsJSON is a specialized implementation of "OrderedMap", where the
// order of the keys is kept track of, and used when serializing the map to
// JSON. While JSON maps do not mandate any particular ordering, and so this
// isn't strictly necessary, it is useful to have a _stable_ serialization
// order for map keys to be compatible with regular Go struct serialization
// behavior. This is also useful for tests/examples that compare encoded
// []byte's.
type structFieldsJSON struct {
	Fields map[string]json.RawMessage
	Keys   []string
}

func newStructFieldsJSON() *structFieldsJSON {
	return &structFieldsJSON{
		Fields: make(map[string]json.RawMessage),
	}
}

func (o structFieldsJSON) Has(key string) bool {
	_, ok := o.Fields[key]
	return ok
}

func (o *structFieldsJSON) Add(key string, val json.RawMessage) error {
	if o.Has(key) {
		return fmt.Errorf("duplicate JSON key: %q", key)
	}

	o.Fields[key] = val
	o.Keys = append(o.Keys, key)

	return nil
}

func (o *structFieldsJSON) Get(key string) (json.RawMessage, bool) {
	val, ok := o.Fields[key]
	return val, ok
}

func (o *structFieldsJSON) Delete(key string) {
	delete(o.Fields, key)

	for i, existing := range o.Keys {
		if existing == key {
			o.Keys = append(o.Keys[:i], o.Keys[i+1:]...)
		}
	}
}

func (o *structFieldsJSON) ToJSON() ([]byte, error) {
	var out bytes.Buffer

	out.Write([]byte("{"))

	first := true
	for _, key := range o.Keys {
		if first {
			first = false
		} else {
			out.Write([]byte(","))
		}
		marshaledKey, err := json.Marshal(key)
		if err != nil {
			return nil, fmt.Errorf("problem marshaling key %s: %w", key, err)
		}
		out.Write(marshaledKey)
		out.Write([]byte(":"))
		out.Write(o.Fields[key])
	}

	out.Write([]byte("}"))

	return out.Bytes(), nil
}

func (o *structFieldsJSON) FromJSON(data []byte) error {
	if err := json.Unmarshal(data, &o.Fields); err != nil {
		return err
	}

	return o.unmarshalKeys(data)
}

func (o *structFieldsJSON) unmarshalKeys(data []byte) error {

	decoder := json.NewDecoder(bytes.NewReader(data))

	token, err := decoder.Token()
	if err != nil {
		return err
	}

	if token != json.Delim('{') {
		return errors.New("expected start of object")
	}

	var keys []string

	for {
		token, err = decoder.Token()
		if err != nil {
			return err
		}

		if token == json.Delim('}') {
			break
		}

		key, ok := token.(string)
		if !ok {
			return fmt.Errorf("expected string, found %T", token)
		}

		keys = append(keys, key)

		if err := skipValue(decoder); err != nil {
			return err
		}
	}

	o.Keys = keys

	return nil
}

var errEndOfStream = errors.New("invalid end of array or object")

func skipValue(decoder *json.Decoder) error {

	token, err := decoder.Token()
	if err != nil {
		return err
	}
	switch token {
	case json.Delim('['), json.Delim('{'):
		for {
			if err := skipValue(decoder); err != nil {
				if err == errEndOfStream {
					break
				}
				return err
			}
		}
	case json.Delim(']'), json.Delim('}'):
		return errEndOfStream
	}
	return nil
}

func doGetProfileJSONTag(structType reflect.Type, structVal reflect.Value) (string, error) {
	var foundByCBORKey *reflect.StructField
	var foundByFieldName *reflect.StructField
	var embeds []embedded

	for i := 0; i < structVal.NumField(); i++ {
		typeField := structType.Field(i)
		valField := structVal.Field(i)

		if collectEmbedded(&typeField, valField, &embeds) {
			continue
		}

		cborTag, ok := typeField.Tag.Lookup("cbor")
		if ok {
			cborKey := strings.Split(cborTag, ",")[0]
			if cborKey == "265" || cborKey == "-75000" { // eat_profile or psa-profile
				foundByCBORKey = &typeField
				break
			}
		} else if typeField.Name == "Profile" {
			foundByFieldName = &typeField
			// note: not breaking here as there could be
			// the CBOR profile tag in a later field, and
			// we want to use that in preference to the
			// field name.
		}

	}

	var jsonTag string
	var ok bool

	if foundByCBORKey != nil {
		jsonTag, ok = foundByCBORKey.Tag.Lookup("json")
	} else if foundByFieldName != nil {
		jsonTag, ok = foundByFieldName.Tag.Lookup("json")
	} else {
		for _, embed := range embeds {
			v, err := doGetProfileJSONTag(embed.Type, embed.Value)
			if err == nil {
				return v, nil
			} else if !errors.Is(err, errNoProfile) {
				return "", err
			}
		}

		return "", errNoProfile
	}

	if !ok {
		return "", errors.New(`no "json" tag associated with profile field`)
	}

	return strings.Split(jsonTag, ",")[0], nil
}
