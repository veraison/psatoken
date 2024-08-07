// Copyright 2021-2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package psatoken

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_DecodeClaims_p1_ok(t *testing.T) {
	tvs := []string{
		testEncodedP1ClaimsAllNoSwMeasurements,
		testEncodedP1ClaimsMandatoryOnlyNoSwMeasurements,
		testEncodedP1ClaimsAll,
		testEncodedP1ClaimsMandatoryOnly,
		testEncodedP1ClaimsTFM,
	}

	for _, tv := range tvs {
		buf := mustHexDecode(t, tv)
		c, err := DecodeAndValidateClaimsFromCBOR(buf)

		assert.NoError(t, err)

		actualProfile, err := c.GetProfile()
		assert.NoError(t, err)
		assert.Equal(t, Profile1Name, actualProfile)
	}
}

func Test_DecodeClaims_p1_failure(t *testing.T) {
	tvs := []string{
		testEncodedP1ClaimsMissingMandatoryNonce,
	}

	for _, tv := range tvs {
		buf := mustHexDecode(t, tv)
		_, err := DecodeAndValidateClaimsFromCBOR(buf)

		expectedError := `validating nonce: missing mandatory claim`

		assert.EqualError(t, err, expectedError)
	}
}

func Test_DecodeClaims_p2_ok(t *testing.T) {
	tvs := []string{
		testEncodedP2ClaimsAll,
		testEncodedP2ClaimsMandatoryOnly,
		testEncodedP2ClaimsTFM,
	}

	for _, tv := range tvs {
		buf := mustHexDecode(t, tv)
		c, err := DecodeAndValidateClaimsFromCBOR(buf)

		assert.NoError(t, err)

		actualProfile, err := c.GetProfile()
		assert.NoError(t, err)
		assert.Equal(t, Profile2Name, actualProfile)
	}
}

func Test_DecodeClaims_p2_failure(t *testing.T) {
	tvs := []string{
		testEncodedP2ClaimsMissingMandatoryNonce,
	}

	for _, tv := range tvs {
		buf := mustHexDecode(t, tv)
		_, err := DecodeAndValidateClaimsFromCBOR(buf)

		expectedError := `validating nonce: missing mandatory claim`

		assert.EqualError(t, err, expectedError)
	}
}

func Test_DecodeUnvalidatedClaims(t *testing.T) {
	type TestVector struct {
		Input    string
		Expected interface{}
	}

	tvs := []TestVector{
		{testEncodedP1ClaimsMissingMandatoryNonce, &P1Claims{}},
		{testEncodedP2ClaimsMissingMandatoryNonce, &P2Claims{}},
	}

	for _, tv := range tvs {
		buf := mustHexDecode(t, tv.Input)
		v, err := DecodeClaimsFromCBOR(buf)

		assert.NoError(t, err)
		assert.IsType(t, tv.Expected, v)
	}
}

func Test_NewClaims_p1_ok(t *testing.T) {
	c, err := NewClaims(Profile1Name)
	assert.NoError(t, err)

	p, err := c.GetProfile()
	assert.NoError(t, err)
	assert.Equal(t, Profile1Name, p)
}

func Test_NewClaims_p2_ok(t *testing.T) {
	c, err := NewClaims(Profile2Name)
	assert.NoError(t, err)

	p, err := c.GetProfile()
	assert.NoError(t, err)
	assert.Equal(t, Profile2Name, p)
}

func Test_NewClaims_profile_unknown(t *testing.T) {
	expectedErr := `unsupported profile "http://unknown.example"`

	_, err := NewClaims("http://unknown.example")
	assert.EqualError(t, err, expectedErr)
}

func makeIClaims(t *testing.T) []IClaims {
	c1 := newP1Claims(true)

	c2 := newP2Claims()

	return []IClaims{c1, c2}
}

func Test_IClaims_SetSecurityLifecycle_invalid(t *testing.T) {
	tv := makeIClaims(t)

	expectedErr := `wrong syntax: value 65535 is invalid`

	for _, c := range tv {
		err := c.SetSecurityLifeCycle(0xffff)
		assert.EqualError(t, err, expectedErr)
	}
}

func Test_IClaims_SetImplID_invalid(t *testing.T) {
	tv := makeIClaims(t)

	expectedErr := `wrong syntax: invalid length 0 (MUST be 32 bytes)`

	for _, c := range tv {
		err := c.SetImplID([]byte{})
		assert.EqualError(t, err, expectedErr)
	}
}

func Test_IClaims_SetInstID_invalid(t *testing.T) {
	tv := makeIClaims(t)

	expectedErr := `wrong syntax: invalid length 0 (MUST be 33 bytes)`

	for _, c := range tv {
		err := c.SetInstID([]byte{})
		assert.EqualError(t, err, expectedErr)
	}
}

func Test_IClaims_SetNonce_invalid(t *testing.T) {
	tv := makeIClaims(t)

	expectedErr := `wrong syntax: length 0 (hash MUST be 32, 48 or 64 bytes)`

	for _, c := range tv {
		err := c.SetNonce([]byte{})
		assert.EqualError(t, err, expectedErr)
	}
}

func Test_IClaims_SetBootSeed_invalid(t *testing.T) {
	tv := makeIClaims(t)

	expectedErrs := []string{
		`wrong syntax: invalid length 0 (MUST be 32 bytes)`,
		`wrong syntax: invalid length 0 (MUST be between 8 and 32 bytes)`,
	}

	for i, c := range tv {
		err := c.SetBootSeed([]byte{})
		assert.EqualError(t, err, expectedErrs[i])
	}
}

func Test_IClaims_SetCertificationReference_invalid(t *testing.T) {
	tv := makeIClaims(t)

	expectedErr := `wrong syntax: MUST be in EAN-13`

	for _, c := range tv {
		for _, s := range []string{"", "abc", "123456789012", "1234567890123+1234S"} {
			err := c.SetCertificationReference(s)
			assert.ErrorContains(t, err, expectedErr)
		}
	}
}

func Test_IClaims_SetVSI_invalid(t *testing.T) {
	tv := makeIClaims(t)

	expectedErr := `wrong syntax: empty string`

	for _, c := range tv {
		err := c.SetVSI("")
		assert.EqualError(t, err, expectedErr)
	}
}

func Test_IClaims_SetSoftwareComponents_invalid(t *testing.T) {
	tv := makeIClaims(t)

	scs := []ISwComponent{
		&SwComponent{
			SignerID: &testSignerID,
		},
	}

	expectedErr := `failed at index 0: measurement value: missing mandatory field`

	for _, c := range tv {
		err := c.SetSoftwareComponents(scs)
		assert.EqualError(t, err, expectedErr)
	}
}

func Test_ToJSON_invalid(t *testing.T) {
	for _, p := range []string{Profile1Name, Profile2Name} {
		c, err := NewClaims(p)
		require.NoError(t, err)

		expectedErr := `validating security lifecycle: missing mandatory claim`

		_, err = ValidateAndEncodeClaimsToJSON(c)
		assert.EqualError(t, err, expectedErr)
	}
}

func Test_DecodeJSONClaims_P2(t *testing.T) {
	buf, err := os.ReadFile("testvectors/json/test-token-valid-minimalist-p2.json")
	require.NoError(t, err)

	c, err := DecodeAndValidateClaimsFromJSON(buf)
	assert.NoError(t, err)
	actualProfile, err := c.GetProfile()
	assert.NoError(t, err)
	assert.Equal(t, Profile2Name, actualProfile)
}

func Test_DecodeJSONClaims_P1(t *testing.T) {
	buf, err := os.ReadFile("testvectors/json/test-token-valid-minimalist-p1.json")
	require.NoError(t, err)

	c, err := DecodeAndValidateClaimsFromJSON(buf)
	assert.NoError(t, err)
	actualProfile, err := c.GetProfile()
	assert.NoError(t, err)
	assert.Equal(t, Profile1Name, actualProfile)
}

func Test_DecodeUnvalidatedJSONClaims(t *testing.T) {
	type TestVector struct {
		Path     string
		Expected interface{}
	}
	tvs := []TestVector{
		// valid
		{"testvectors/json/test-token-valid-minimalist-p1.json", &P1Claims{}},
		{"testvectors/json/test-token-valid-minimalist-p2.json", &P2Claims{}},

		// invalid
		{"testvectors/json/test-boot-seed-invalid-long.json", &P2Claims{}},
		{"testvectors/json/test-boot-seed-invalid-missing.json", &P2Claims{}},
		{"testvectors/json/test-hardware-version-invalid.json", &P2Claims{}},
		{"testvectors/json/test-sw-components-invalid-missing.json", &P2Claims{}},
		{"testvectors/json/test-security-lifecycle-invalid-state.json", &P2Claims{}},
	}

	for _, tv := range tvs {
		buf, err := os.ReadFile(tv.Path)
		require.NoError(t, err)

		v, err := DecodeClaimsFromJSON(buf)

		assert.NoError(t, err)
		assert.IsType(t, tv.Expected, v)
	}
}
