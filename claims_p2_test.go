// Copyright 2021-2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package psatoken

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustBuildValidP2Claims(t *testing.T, includeOptional bool) IClaims {
	c, err := newP2Claims()
	require.NoError(t, err)

	err = c.SetClientID(testClientIDSPE)
	require.NoError(t, err)

	err = c.SetSecurityLifeCycle(testSecurityLifecycleSecured)
	require.NoError(t, err)

	err = c.SetImplID(testImplementationID)
	require.NoError(t, err)

	err = c.SetNonce(testNonce)
	require.NoError(t, err)

	err = c.SetInstID(testInstID)
	require.NoError(t, err)

	err = c.SetSoftwareComponents(testSoftwareComponents)
	require.NoError(t, err)

	if includeOptional {
		err = c.SetBootSeed(testBootSeedMin)
		require.NoError(t, err)

		err = c.SetCertificationReference(testCertificationReferenceP2)
		require.NoError(t, err)

		err = c.SetVSI(testVSI)
		require.NoError(t, err)
	}

	return c
}

func Test_NewP2Claims_ok(t *testing.T) {
	c, err := newP2Claims()
	assert.NoError(t, err)

	expected := PsaProfile2

	actual, err := c.GetProfile()
	assert.NoError(t, err)
	assert.Equal(t, expected, actual)
}

func Test_P2Claims_Validate_all_claims(t *testing.T) {
	c := mustBuildValidP2Claims(t, true)

	err := c.Validate()
	assert.NoError(t, err)
}

func Test_P2Claims_Validate_mandatory_only_claims(t *testing.T) {
	c := mustBuildValidP2Claims(t, false)

	err := c.Validate()
	assert.NoError(t, err)
}

func Test_P2Claims_ToCBOR_invalid(t *testing.T) {
	c, err := newP2Claims()
	require.NoError(t, err)

	expectedErr := `validation of PSA claims failed: validating psa-client-id: missing mandatory claim`

	_, err = c.ToCBOR()

	assert.EqualError(t, err, expectedErr)
}

func Test_P2Claims_ToCBOR_all_claims(t *testing.T) {
	c := mustBuildValidP2Claims(t, true)

	expected := mustHexDecode(t, testEncodedP2ClaimsAll)

	actual, err := c.ToCBOR()

	assert.NoError(t, err)
	assert.Equal(t, expected, actual)
}

func Test_P2Claims_ToCBOR_mandatory_only_claims(t *testing.T) {
	c := mustBuildValidP2Claims(t, false)

	expected := mustHexDecode(t, testEncodedP2ClaimsMandatoryOnly)

	actual, err := c.ToCBOR()

	assert.NoError(t, err)
	assert.Equal(t, expected, actual)
}

func Test_P2Claims_FromCBOR_bad_input(t *testing.T) {
	buf := mustHexDecode(t, testNotCBOR)

	expectedErr := "CBOR decoding of PSA claims failed: unexpected EOF"

	var c P2Claims
	err := c.FromCBOR(buf)

	assert.EqualError(t, err, expectedErr)
}

func Test_P2Claims_FromCBOR_missing_mandatory_claim(t *testing.T) {
	buf := mustHexDecode(t, testEncodedP2ClaimsMissingMandatoryNonce)

	expectedErr := "validation of PSA claims failed: validating psa-nonce: missing mandatory claim"

	var c P2Claims
	err := c.FromCBOR(buf)

	assert.EqualError(t, err, expectedErr)
}

func Test_P2Claims_FromCBOR_invalid_multi_nonce(t *testing.T) {
	buf := mustHexDecode(t, testEncodedP2ClaimsInvalidMultiNonce)

	expectedErr := "validation of PSA claims failed: validating psa-nonce: wrong syntax for claim: got 2 nonces, want 1"

	var c P2Claims
	err := c.FromCBOR(buf)

	assert.EqualError(t, err, expectedErr)
}

func Test_P2Claims_FromCBOR_ok_mandatory_only(t *testing.T) {
	buf := mustHexDecode(t, testEncodedP2ClaimsMandatoryOnly)

	var c P2Claims
	err := c.FromCBOR(buf)
	assert.NoError(t, err)

	// mandatory

	expectedProfile := PsaProfile2
	actualProfile, err := c.GetProfile()
	assert.NoError(t, err)
	assert.Equal(t, expectedProfile, actualProfile)

	expectedClientID := testClientIDSPE
	actualClientID, err := c.GetClientID()
	assert.NoError(t, err)
	assert.Equal(t, expectedClientID, actualClientID)

	expectedSecurityLifeCycle := testSecurityLifecycleSecured
	actualSecurityLifeCycle, err := c.GetSecurityLifeCycle()
	assert.NoError(t, err)
	assert.Equal(t, expectedSecurityLifeCycle, actualSecurityLifeCycle)

	expectedImplID := testImplementationID
	actualImplID, err := c.GetImplID()
	assert.NoError(t, err)
	assert.Equal(t, expectedImplID, actualImplID)

	expectedNonce := testNonce
	actualNonce, err := c.GetNonce()
	assert.NoError(t, err)
	assert.Equal(t, expectedNonce, actualNonce)

	expectedInstID := testInstID
	actualInstID, err := c.GetInstID()
	assert.NoError(t, err)
	assert.Equal(t, expectedInstID, actualInstID)

	expectedSwComp := testSoftwareComponents
	actualSwComp, err := c.GetSoftwareComponents()
	assert.NoError(t, err)
	assert.Equal(t, expectedSwComp, actualSwComp)

	// optional (missing)
	// note that boot-seed is optional in P2

	expectedError := ErrOptionalClaimMissing
	_, err = c.GetVSI()
	assert.Equal(t, err, expectedError)

	expectedError = ErrOptionalClaimMissing
	_, err = c.GetBootSeed()
	assert.Equal(t, err, expectedError)

	expectedError = ErrOptionalClaimMissing
	_, err = c.GetCertificationReference()
	assert.Equal(t, err, expectedError)
}

func Test_P2Claims_Validate_positives(t *testing.T) {
	validatePositives(t, PsaProfile2)
}

func Test_P2Claims_Validate_negatives(t *testing.T) {
	validateNegatives(t, PsaProfile2)
}

func Test_P2Claims_SetSecurityLifecycle_invalid(t *testing.T) {
	c, err := newP2Claims()
	require.NoError(t, err)

	expectedErr := `wrong syntax for claim: value 65535 is invalid`

	err = c.SetSecurityLifeCycle(0xffff)
	assert.EqualError(t, err, expectedErr)
}
