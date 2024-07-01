// Copyright 2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package psatoken

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_SwComponent_setters(t *testing.T) {
	sc := SwComponent{}
	buf := mustHexDecode(t, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
	badBuf := mustHexDecode(t, "dead")

	err := sc.SetMeasurementType("foo")
	require.NoError(t, err)
	assert.Equal(t, "foo", *sc.MeasurementType)

	err = sc.SetMeasurementValue(buf)
	require.NoError(t, err)
	assert.Equal(t, buf, *sc.MeasurementValue)

	err = sc.SetMeasurementValue(badBuf)
	assert.EqualError(t, err, "wrong syntax: length 2 (hash MUST be 32, 48 or 64 bytes)")

	err = sc.SetVersion("bar")
	require.NoError(t, err)
	assert.Equal(t, "bar", *sc.Version)

	err = sc.SetSignerID(buf)
	require.NoError(t, err)
	assert.Equal(t, buf, *sc.SignerID)

	err = sc.SetSignerID(badBuf)
	assert.EqualError(t, err, "wrong syntax: length 2 (hash MUST be 32, 48 or 64 bytes)")

	err = sc.SetMeasurementDesc("buzz")
	require.NoError(t, err)
	assert.Equal(t, "buzz", *sc.MeasurementDesc)
}
