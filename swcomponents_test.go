// Copyright 2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package psatoken

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_SwComponents_Validate(t *testing.T) {
	scs := SwComponents[*SwComponent]{
		values: []*SwComponent{
			{
				MeasurementValue: &testMeasurementValue,
				SignerID:         &testSignerID,
			},
		},
	}

	assert.NoError(t, scs.Validate())

	scs = SwComponents[*SwComponent]{
		values: []*SwComponent{
			{
				MeasurementValue: &testMeasurementValue,
			},
		},
	}

	err := scs.Validate()
	assert.EqualError(t, err, "failed at index 0: signer ID: missing mandatory field")
}

func Test_SwComponents_Add(t *testing.T) {
	scs := SwComponents[*SwComponent]{
		values: []*SwComponent{
			{
				MeasurementValue: &testMeasurementValue,
				SignerID:         &testSignerID,
			},
		},
	}

	err := scs.Add(&SwComponent{
		MeasurementValue: &testMeasurementValue,
		SignerID:         &testSignerID,
	})

	require.NoError(t, err)
	assert.Len(t, scs.values, 2)

	err = scs.Add(&SwComponent{
		MeasurementValue: &testMeasurementValue,
	})
	assert.EqualError(t, err, "failed at index 0: signer ID: missing mandatory field")
}
