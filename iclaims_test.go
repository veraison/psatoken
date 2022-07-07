// Copyright 2021-2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package psatoken

import (
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
		c, err := DecodeClaims(buf)

		assert.NoError(t, err)

		actualProfile, err := c.GetProfile()
		assert.NoError(t, err)
		assert.Equal(t, PsaProfile1, actualProfile)
	}
}

func Test_DecodeClaims_p1_failure(t *testing.T) {
	tvs := []string{
		testEncodedP1ClaimsMissingMandatoryNonce,
	}

	for _, tv := range tvs {
		buf := mustHexDecode(t, tv)
		_, err := DecodeClaims(buf)

		expectedError := `decode failed for both p1 (validation of PSA claims failed: validating psa-nonce: missing mandatory claim) and p2 (validation of PSA claims failed: validating profile: missing mandatory claim)`

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
		c, err := DecodeClaims(buf)

		assert.NoError(t, err)

		actualProfile, err := c.GetProfile()
		assert.NoError(t, err)
		assert.Equal(t, PsaProfile2, actualProfile)
	}
}

func Test_DecodeClaims_p2_failure(t *testing.T) {
	tvs := []string{
		testEncodedP2ClaimsMissingMandatoryNonce,
	}

	for _, tv := range tvs {
		buf := mustHexDecode(t, tv)
		_, err := DecodeClaims(buf)

		expectedError := `decode failed for both p1 (validation of PSA claims failed: validating psa-client-id: missing mandatory claim) and p2 (validation of PSA claims failed: validating psa-nonce: missing mandatory claim)`

		assert.EqualError(t, err, expectedError)
	}
}

func Test_NewClaims_p1_ok(t *testing.T) {
	c, err := NewClaims(PsaProfile1)
	assert.NoError(t, err)

	p, err := c.GetProfile()
	assert.NoError(t, err)
	assert.Equal(t, PsaProfile1, p)
}

func Test_NewClaims_p2_ok(t *testing.T) {
	c, err := NewClaims(PsaProfile2)
	assert.NoError(t, err)

	p, err := c.GetProfile()
	assert.NoError(t, err)
	assert.Equal(t, PsaProfile2, p)
}

func Test_NewClaims_profile_unknown(t *testing.T) {
	expectedErr := `unsupported profile "http://unknown.example"`

	_, err := NewClaims("http://unknown.example")
	assert.EqualError(t, err, expectedErr)
}

func makeIClaims(t *testing.T) []IClaims {
	c1, err := newP1Claims(true)
	require.NoError(t, err)

	c2, err := newP2Claims()
	require.NoError(t, err)

	return []IClaims{c1, c2}
}

func Test_IClaims_SetSecurityLifecycle_invalid(t *testing.T) {
	tv := makeIClaims(t)

	expectedErr := `wrong syntax for claim: value 65535 is invalid`

	for _, c := range tv {
		err := c.SetSecurityLifeCycle(0xffff)
		assert.EqualError(t, err, expectedErr)
	}
}

func Test_IClaims_SetImplID_invalid(t *testing.T) {
	tv := makeIClaims(t)

	expectedErr := `wrong syntax for claim: invalid length 0 (MUST be 32 bytes)`

	for _, c := range tv {
		err := c.SetImplID([]byte{})
		assert.EqualError(t, err, expectedErr)
	}
}

func Test_IClaims_SetInstID_invalid(t *testing.T) {
	tv := makeIClaims(t)

	expectedErr := `wrong syntax for claim: invalid length 0 (MUST be 33 bytes)`

	for _, c := range tv {
		err := c.SetInstID([]byte{})
		assert.EqualError(t, err, expectedErr)
	}
}

func Test_IClaims_SetNonce_invalid(t *testing.T) {
	tv := makeIClaims(t)

	expectedErr := `wrong syntax for claim: length 0 (psa-hash-type MUST be 32, 48 or 64 bytes)`

	for _, c := range tv {
		err := c.SetNonce([]byte{})
		assert.EqualError(t, err, expectedErr)
	}
}

func Test_IClaims_SetBootSeed_invalid(t *testing.T) {
	tv := makeIClaims(t)

	expectedErrs := []string{
		`wrong syntax for claim: invalid length 0 (MUST be 32 bytes)`,
		`wrong syntax for claim: invalid length 0 (MUST be between 8 and 32 bytes)`,
	}

	for i, c := range tv {
		err := c.SetBootSeed([]byte{})
		assert.EqualError(t, err, expectedErrs[i])
	}
}

func Test_IClaims_SetCertificationReference_invalid(t *testing.T) {
	tv := makeIClaims(t)

	expectedErr := `wrong syntax for claim: MUST be in EAN-13`

	for _, c := range tv {
		err := c.SetCertificationReference("")
		assert.ErrorContains(t, err, expectedErr)
	}
}

func Test_IClaims_SetVSI_invalid(t *testing.T) {
	tv := makeIClaims(t)

	expectedErr := `wrong syntax for claim: empty string`

	for _, c := range tv {
		err := c.SetVSI("")
		assert.EqualError(t, err, expectedErr)
	}
}

func Test_IClaims_SetSoftwareComponents_invalid(t *testing.T) {
	tv := makeIClaims(t)

	scs := []SwComponent{
		{
			SignerID: &testSignerID,
		},
	}

	expectedErr := `failed at index 0: missing mandatory measurement-value`

	for _, c := range tv {
		err := c.SetSoftwareComponents(scs)
		assert.EqualError(t, err, expectedErr)
	}
}
