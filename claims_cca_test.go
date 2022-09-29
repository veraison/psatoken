package psatoken

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustBuildValidCcaPlatformClaims(t *testing.T, includeOptional bool) IClaims {
	c, err := newCcaPlatformClaims()
	require.NoError(t, err)

	err = c.SetSecurityLifeCycle(testCcaLifeCycleSecured)
	require.NoError(t, err)

	err = c.SetImplID(testImplementationID)
	require.NoError(t, err)

	err = c.SetNonce(testNonce)
	require.NoError(t, err)

	err = c.SetInstID(testInstID)
	require.NoError(t, err)

	err = c.SetSoftwareComponents(testSoftwareComponents)
	require.NoError(t, err)

	err = c.SetHashAlgID(testHashAlgID)
	require.NoError(t, err)

	err = c.SetConfig(testConfig)
	require.NoError(t, err)

	if includeOptional {
		err = c.SetVSI(testVSI)
		require.NoError(t, err)
	}

	return c
}

func Test_NewCcaPlatformClaims_ok(t *testing.T) {
	c, err := newCcaPlatformClaims()
	assert.NoError(t, err)

	expected := CcaProfile

	actual, err := c.GetProfile()
	assert.NoError(t, err)
	assert.Equal(t, expected, actual)
}

func Test_CcaPlatformClaims_Validate_all_claims(t *testing.T) {
	c := mustBuildValidCcaPlatformClaims(t, true)

	err := c.Validate()
	assert.NoError(t, err)
}

func Test_CcaPlatformClaims_Validate_mandatory_only_claims(t *testing.T) {
	c := mustBuildValidCcaPlatformClaims(t, false)

	err := c.Validate()
	assert.NoError(t, err)
}

func Test_CcaPlatformClaims_Set_NonValid_Claims(t *testing.T) {
	var c CcaPlatformClaims

	err := c.SetBootSeed([]byte("123"))
	expectedErr := "invalid SetBootSeed invoked on CCA platform claims"
	assert.EqualError(t, err, expectedErr)

	err = c.SetCertificationReference("testCertification")
	expectedErr = "invalid SetCertificationReference invoked on CCA platform claims"
	assert.EqualError(t, err, expectedErr)

	err = c.SetClientID(1)
	expectedErr = "invalid SetClientID invoked on CCA platform claims"
	assert.EqualError(t, err, expectedErr)

	err = c.SetConfig([]byte{})
	expectedErr = "missing mandatory claim"
	assert.EqualError(t, err, expectedErr)

	err = c.SetHashAlgID("non existent")
	expectedErr = "wrong syntax for claim: wrong syntax"
	assert.EqualError(t, err, expectedErr)

	err = c.SetHashAlgID("")
	expectedErr = "wrong syntax for claim: empty string"
	assert.EqualError(t, err, expectedErr)
}

func Test_CcaPlatformClaims_Get_NonValid_Claims(t *testing.T) {
	var c CcaPlatformClaims

	_, err := c.GetBootSeed()
	expectedErr := "invalid GetBootSeed invoked on CCA platform claims"
	assert.EqualError(t, err, expectedErr)

	_, err = c.GetCertificationReference()
	expectedErr = "invalid GetCertificationReference invoked on CCA platform claims"
	assert.EqualError(t, err, expectedErr)

	_, err = c.GetClientID()
	expectedErr = "invalid GetClientID invoked on CCA platform claims"
	assert.EqualError(t, err, expectedErr)

}

func Test_CcaPlatform_Claims_ToCBOR_invalid(t *testing.T) {
	c, err := newCcaPlatformClaims()
	require.NoError(t, err)

	expectedErr := `validation of CCA platform claims failed: validating psa-security-lifecycle: missing mandatory claim`

	_, err = c.ToCBOR()

	assert.EqualError(t, err, expectedErr)
}

func Test_CcaPlatform_Claims_ToCBOR_all_claims(t *testing.T) {
	c := mustBuildValidCcaPlatformClaims(t, true)

	expected := mustHexDecode(t, testEncodedCcaPlatformClaimsAll)

	actual, err := c.ToCBOR()

	assert.NoError(t, err)
	assert.Equal(t, expected, actual)
}

func Test_CcaPlatform_Claims_ToCBOR_mandatory_only_claims(t *testing.T) {
	c := mustBuildValidCcaPlatformClaims(t, false)

	expected := mustHexDecode(t, testEncodedCcaPlatformClaimsMandatoryOnly)

	actual, err := c.ToCBOR()

	assert.NoError(t, err)
	assert.Equal(t, expected, actual)
}

func Test_CcaPlatform_FromCBOR_ok_mandatory_only(t *testing.T) {
	buf := mustHexDecode(t, testEncodedCcaPlatformClaimsMandatoryOnly)

	var c CcaPlatformClaims
	err := c.FromCBOR(buf)
	assert.NoError(t, err)

	// mandatory

	expectedProfile := CcaProfile
	actualProfile, err := c.GetProfile()
	assert.NoError(t, err)
	assert.Equal(t, expectedProfile, actualProfile)

	expectedCcaLifeCycle := testCcaLifeCycleSecured
	actualCcaLifeCycle, err := c.GetSecurityLifeCycle()
	assert.NoError(t, err)
	assert.Equal(t, expectedCcaLifeCycle, actualCcaLifeCycle)

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

}

func Test_CcaPlatform_Claims_FromCBOR_bad_input(t *testing.T) {
	buf := mustHexDecode(t, testNotCBOR)

	expectedErr := "CBOR decoding of CCA platform claims failed: unexpected EOF"

	var c CcaPlatformClaims
	err := c.FromCBOR(buf)

	assert.EqualError(t, err, expectedErr)
}

func Test_CcaPlatform_Claims_FromCBOR_missing_mandatory_claim(t *testing.T) {
	buf := mustHexDecode(t, testEncodedCcaPlatformClaimsMissingMandatoryNonce)

	expectedErr := "validation of CCA platform claims failed: validating psa-nonce: missing mandatory claim"

	var c CcaPlatformClaims
	err := c.FromCBOR(buf)

	assert.EqualError(t, err, expectedErr)
}

func Test_CcaPlatform_Claims_FromCBOR_invalid_multi_nonce(t *testing.T) {
	buf := mustHexDecode(t, testEncodedCcaPlatformClaimsInvalidMultiNonce)

	expectedErr := "validation of CCA platform claims failed: validating psa-nonce: wrong syntax for claim: got 2 nonces, want 1"

	var c CcaPlatformClaims
	err := c.FromCBOR(buf)

	assert.EqualError(t, err, expectedErr)
}

func Test_CcaPlatform_ToJSON_ok(t *testing.T) {
	c := mustBuildValidCcaPlatformClaims(t, true)

	expected := `{
	   "cca-platform-profile": "http://arm.com/CCA-SSD/1.0.0",
	   "cca-platform-challenge":  "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
	   "cca-platform-implementation-id":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	   "cca-platform-instance-id": "AQICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC",
	   "cca-platform-config": "AQID",
	   "cca-platform-lifecycle": 12288,
	   "cca-platform-sw-components": [
	   	  {
	   		"measurement-value": "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=",
	   		"signer-id": "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ="
	   	  }
	   	],
	   "cca-platform-service-indicator" : "https://veraison.example/v1/challenge-response",
	   "cca-platform-hash-algo-id": "sha-256"
	   }`
	actual, err := c.ToJSON()
	assert.NoError(t, err)
	assert.JSONEq(t, expected, string(actual))
}

func Test_CcaPlatform_ToJSON_not_ok(t *testing.T) {
	c := CcaPlatformClaims{}
	expectedErr := `validation of CCA platform claims failed: validating profile: missing mandatory claim`
	_, err := c.ToJSON()
	assert.EqualError(t, err, expectedErr)
}

func Test_CcaPlatform_FromJSON_ok(t *testing.T) {
	tv := `{
		"cca-platform-profile": "http://arm.com/CCA-SSD/1.0.0",
		"cca-platform-challenge":  "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
		"cca-platform-implementation-id":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"cca-platform-instance-id": "AQICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC",
		"cca-platform-config": "AQID",
		"cca-platform-lifecycle": 12288,
		"cca-platform-sw-components": [
			  {
				"measurement-value": "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=",
				"signer-id": "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ="
			  }
			],
		"cca-platform-service-indicator" : "https://veraison.example/v1/challenge-response",
		"cca-platform-hash-algo-id": "sha-256"
		}`

	var c CcaPlatformClaims

	err := c.FromJSON([]byte(tv))
	assert.NoError(t, err)
}

func Test_CcaPlatform_FromJSON_invalid_json(t *testing.T) {
	tv := testNotJSON

	expectedErr := `JSON decoding of CCA platform claims failed: unexpected end of JSON input`

	var c CcaPlatformClaims

	err := c.FromJSON(tv)
	assert.EqualError(t, err, expectedErr)
}

func Test_CcaPlatform_FromJSON_negatives(t *testing.T) {
	tvs := []string{
		/* 0 */ "testvectors/json/ccatoken/test-invalid-profile.json",
		/* 1 */ "testvectors/json/ccatoken/test-vsi-invalid-empty.json",
		/* 2 */ "testvectors/json/ccatoken/test-implementation-id-invalid-long.json",
		/* 3 */ "testvectors/json/ccatoken/test-implementation-id-invalid-missing.json",
		/* 4 */ "testvectors/json/ccatoken/test-no-sw-components.json",
		/* 5 */ "testvectors/json/ccatoken/test-sw-components-invalid-combo.json",
		/* 6 */ "testvectors/json/ccatoken/test-hash-algid-invalid.json",
		/* 7 */ "testvectors/json/ccatoken/test-no-sw-components.json",
		/* 8 */ "testvectors/json/ccatoken/test-lifecycle-invalid.json",
		/* 9 */ "testvectors/json/ccatoken/test-sw-components-invalid-missing.json",
		/* 10 */ "testvectors/json/ccatoken/test-nonce-invalid.json",
		/* 11 */ "testvectors/json/ccatoken/test-instance-id-missing.json",
		/* 12 */ "testvectors/json/ccatoken/test-instance-id-invalid.json",
		/* 13 */ "testvectors/json/ccatoken/test-config-missing.json",
		/* 14 */ "testvectors/json/ccatoken/test-hash-algid-missing.json",
	}

	for i, fn := range tvs {
		buf, err := os.ReadFile(fn)
		require.NoError(t, err)

		var claimsSet CcaPlatformClaims

		err = claimsSet.FromJSON(buf)
		assert.Error(t, err, "test vector %d failed", i)
	}
}
