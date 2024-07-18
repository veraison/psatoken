// Copyright 2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package encoding

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_PopulateStructFromJSON(t *testing.T) {
	type SimpleStruct struct {
		FieldOne     string `json:"field-one,omitempty"`
		FieldTwo     int    `json:"field-two"`
		IgnoredField int    `json:"-"`
	}

	var v SimpleStruct

	data := []byte(`{"field-one": "acme", "field-two": 6}`)

	err := PopulateStructFromJSON(data, &v)
	require.NoError(t, err)
	assert.Equal(t, "acme", v.FieldOne)
	assert.Equal(t, 6, v.FieldTwo)

	data = []byte(`{"field-two": 6}`)
	v = SimpleStruct{}

	err = PopulateStructFromJSON(data, &v)
	require.NoError(t, err)
	assert.Equal(t, "", v.FieldOne)
	assert.Equal(t, 6, v.FieldTwo)

	data = []byte(`{"field-one": "acme"}`)
	v = SimpleStruct{}

	err = PopulateStructFromJSON(data, &v)
	assert.EqualError(t, err, `missing mandatory field "FieldTwo" ("field-two")`)

	err = PopulateStructFromJSON([]byte("7"), &v)
	assert.EqualError(t, err, `json: cannot unmarshal number into Go value of type map[string]json.RawMessage`)

	type CompositeStruct struct {
		FieldThree string `json:"field-three"`
		SimpleStruct
	}

	var c CompositeStruct

	data = []byte(`{"field-one": "acme", "field-two": 6, "field-three": "foo"}`)

	err = PopulateStructFromJSON(data, &c)
	require.NoError(t, err)
	assert.Equal(t, "acme", c.FieldOne)
	assert.Equal(t, 6, c.FieldTwo)
	assert.Equal(t, "foo", c.FieldThree)

	res, err := SerializeStructToJSON(&c)
	require.NoError(t, err)

	var c2 CompositeStruct
	err = PopulateStructFromJSON(res, &c2)
	require.NoError(t, err)
	assert.EqualValues(t, c, c2)

	type MyIface interface{}

	type CompositeStructWithIface struct {
		FieldThree string `json:"field-three"`
		MyIface
	}

	c3 := CompositeStructWithIface{MyIface: &SimpleStruct{}}
	err = PopulateStructFromJSON(res, &c3)
	require.NoError(t, err)

	c3 = CompositeStructWithIface{MyIface: nil}
	err = PopulateStructFromJSON(res, &c3)
	require.NoError(t, err)

	type EmbeddedNonStruct struct {
		int // nolint:unused
	}

	c4 := EmbeddedNonStruct{}
	err = PopulateStructFromJSON(res, &c4)
	require.NoError(t, err)
}

func Test_structFieldsJSON_CRUD(t *testing.T) {
	sf := newStructFieldsJSON()

	err := sf.Add("two", json.RawMessage("2"))
	assert.NoError(t, err)

	err = sf.Add("one", json.RawMessage("1"))
	assert.NoError(t, err)

	err = sf.Add("three", json.RawMessage("3"))
	assert.NoError(t, err)

	assert.Equal(t, []string{"two", "one", "three"}, sf.Keys)
	assert.True(t, sf.Has("three"))
	assert.False(t, sf.Has("four"))

	val, ok := sf.Get("two")
	assert.True(t, ok)
	assert.Equal(t, json.RawMessage("2"), val)

	_, ok = sf.Get("four")
	assert.False(t, ok)

	sf.Delete("two")
	_, ok = sf.Get("two")
	assert.False(t, ok)

	err = sf.Add("one", json.RawMessage("4"))
	assert.EqualError(t, err, `duplicate JSON key: "one"`)
}

func Test_skipValue(t *testing.T) {
	text := ""
	decoder := json.NewDecoder(strings.NewReader(text))
	err := skipValue(decoder)
	assert.EqualError(t, err, "EOF")

	text = "[]"
	decoder = json.NewDecoder(strings.NewReader(text))
	_, _ = decoder.Token() // skip the '['
	err = skipValue(decoder)
	assert.EqualError(t, err, "invalid end of array or object")

	text = `{"embed": {"one": 1, "two": [1,2,3]}, "other": 1}`
	decoder = json.NewDecoder(strings.NewReader(text))
	_, _ = decoder.Token() // skip the '{'
	_, _ = decoder.Token() // skip the '"embed"'
	err = skipValue(decoder)
	assert.NoError(t, err)

	token, err := decoder.Token()
	assert.NoError(t, err)
	assert.Equal(t, "other", token)
}

func Test_GetProfileJSONTag(t *testing.T) {
	type embedded struct {
		Profile string `cbor:"265,keyasint" json:"profile-embedded"`
	}

	tvs := []struct {
		Name  string
		Value interface{}
		Tag   string
		Err   string
	}{
		{
			Name: "ok via cbor tag",
			Value: struct {
				Profile string `cbor:"1,keyasint" json:"profileBad"`
				Field1  string `cbor:"265,keyasint" json:"profile1"`
			}{},
			Tag: "profile1",
		},
		{
			Name: "ok via field name",
			Value: struct {
				Profile string `json:"profile2"`
			}{},
			Tag: "profile2",
		},
		{
			Name: "ok embedded",
			Value: struct {
				embedded
			}{},
			Tag: "profile-embedded",
		},
		{
			Name: "nok no json tag",
			Value: struct {
				Field1 string `cbor:"265,keyasint"`
			}{},
			Err: `no "json" tag associated with profile field`,
		},
		{
			Name: "nok no profile field",
			Value: struct {
			}{},
			Err: `could not identify profile field`,
		},
	}

	for _, tv := range tvs {
		t.Run(tv.Name, func(t *testing.T) {
			tag, err := GetProfileJSONTag(tv.Value)

			if tv.Err == "" {
				assert.Equal(t, tv.Tag, tag)
			} else {
				assert.EqualError(t, err, tv.Err)
			}
		})
	}
}
