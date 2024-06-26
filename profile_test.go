// Copyright 2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package psatoken

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_getJSONTag(t *testing.T) {

	testCases := []struct {
		Name          string
		Value         interface{}
		ExpectedTag   string
		ExpectedError string
	}{
		{
			Name: "from cbor keyasint ok struct",
			Value: struct {
				Field string `cbor:"265,keyasint" json:"profile1"`
			}{},
			ExpectedTag: "profile1",
		},
		{
			Name: "from cbor ok struct",
			Value: struct {
				Field string `cbor:"265" json:"profile2"`
			}{},
			ExpectedTag: "profile2",
		},
		{
			Name: "from cbor ok pointer",
			Value: &struct {
				Field string `cbor:"265" json:"profile3"`
			}{},
			ExpectedTag: "profile3",
		},
		{
			Name: "from name ok",
			Value: struct {
				Profile string `json:"profile4"`
			}{},
			ExpectedTag: "profile4",
		},
		{
			Name: "prefer cbor over name",
			Value: struct {
				Profile string `cbor:"1" json:"profile5"`
				Field   string `cbor:"265" json:"profile6"`
			}{Field: "test", Profile: "test"},
			ExpectedTag: "profile6",
		},
		{
			Name: "no json tag",
			Value: struct {
				Field string `cbor:"265"`
			}{},
			ExpectedError: `no "json" tag`,
		},
		{
			Name: "no profile field",
			Value: struct {
			}{},
			ExpectedError: `could not identify profile field`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			tag, err := getJSONTag(tc.Value)

			if tc.ExpectedTag != "" {
				assert.Equal(t, tc.ExpectedTag, tag)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.ExpectedError)
			}

		})
	}
}
