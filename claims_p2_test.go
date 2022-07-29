// Copyright 2021-2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package psatoken

import (
	"os"
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

func Test_P2Claims_FromJSON_positives(t *testing.T) {
	tvs := []string{
		/* 0 */ "testvectors/json/test-token-valid-full.json",
		/* 1 */ "testvectors/json/test-token-valid-minimalist-p2.json",
		/* 2 */ "testvectors/json/test-boot-seed-invalid-missing.json", // missing boot seed ok for P2
	}

	for i, fn := range tvs {
		buf, err := os.ReadFile(fn)
		require.NoError(t, err)

		var claimsSet P2Claims

		err = claimsSet.FromJSON(buf)
		assert.NoError(t, err, "test vector %d failed", i)
	}
}

func Test_P2Claims_FromJSON_negatives(t *testing.T) {
	tvs := []string{
		/* 0 */ "testvectors/json/test-boot-seed-invalid-long.json",
		/* 1 */ "testvectors/json/test-token-valid-minimalist-no-sw-measurements.json",
		/* 2 */ "testvectors/json/test-boot-seed-invalid-short.json",
		/* 3 */ "testvectors/json/test-client-id-invalid-missing.json",
		/* 4 */ "testvectors/json/test-hardware-version-invalid.json",
		/* 5 */ "testvectors/json/test-implementation-id-invalid-long.json",
		/* 6 */ "testvectors/json/test-implementation-id-invalid-missing.json",
		/* 7 */ "testvectors/json/test-implementation-id-invalid-short.json",
		/* 8 */ "testvectors/json/test-instance-id-invalid-euid-type.json",
		/* 9 */ "testvectors/json/test-instance-id-invalid-long.json",
		/* 10 */ "testvectors/json/test-instance-id-invalid-missing.json",
		/* 11 */ "testvectors/json/test-instance-id-invalid-short.json",
		/* 12 */ "testvectors/json/test-nonce-invalid-long.json",
		/* 13 */ "testvectors/json/test-nonce-invalid-missing.json",
		/* 14 */ "testvectors/json/test-nonce-invalid-short.json",
		/* 15 */ "testvectors/json/test-profile-invalid-unknown.json",
		/* 16 */ "testvectors/json/test-security-lifecycle-invalid-missing.json",
		/* 17 */ "testvectors/json/test-security-lifecycle-invalid-state.json",
		/* 18 */ "testvectors/json/test-sw-component-and-no-sw-measurements-missing.json",
		/* 19 */ "testvectors/json/test-sw-component-measurement-value-invalid-missing.json",
		/* 20 */ "testvectors/json/test-sw-component-measurement-value-invalid-short.json",
		/* 21 */ "testvectors/json/test-sw-component-signer-id-invalid-missing.json",
		/* 22 */ "testvectors/json/test-sw-component-signer-id-invalid-short.json",
		/* 23 */ "testvectors/json/test-sw-components-empty.json",
		/* 24 */ "testvectors/json/test-sw-components-invalid-combo.json",
		/* 25 */ "testvectors/json/test-sw-components-invalid-missing.json",
		/* 26 */ "testvectors/json/test-vsi-invalid-empty.json",
		/* 27 */ "testvectors/json/test-profile-invalid-missing.json", // missing profile defaults to P1
		/* 28 */ "testvectors/json/test-profile-valid-missing.json",
	}

	for i, fn := range tvs {
		buf, err := os.ReadFile(fn)
		require.NoError(t, err)

		var claimsSet P2Claims

		err = claimsSet.FromJSON(buf)
		assert.Error(t, err, "test vector %d failed", i)
	}
}

func TestP2Claims_FromJSON_invalid_json(t *testing.T) {
	tv := testNotJSON

	expectedErr := `JSON decoding of PSA claims failed: unexpected end of JSON input`

	var c P2Claims

	err := c.FromJSON(tv)
	assert.EqualError(t, err, expectedErr)
}

func Test_P2Claims_ToJSON_ok(t *testing.T) {
	c := mustBuildValidP2Claims(t, true)

	expected := `{
	"eat-profile": "http://arm.com/psa/2.0.0",
	"psa-client-id": 2147483647,
	"psa-security-lifecycle": 12288,
	"psa-implementation-id": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	"psa-boot-seed": "AAAAAAAAAAA=",
	"psa-certification-reference": "1234567890123-12345",
	"psa-software-components": [
	  {
		"measurement-value": "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=",
		"signer-id": "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ="
	  }
	],
	"psa-nonce": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
	"psa-instance-id": "AQICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC",
	"psa-verification-service-indicator": "https://veraison.example/v1/challenge-response"	
}`

	actual, err := c.ToJSON()
	assert.NoError(t, err)
	assert.JSONEq(t, expected, string(actual))
}
