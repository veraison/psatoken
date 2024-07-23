// Copyright 2021-2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package psatoken

import (
	"crypto"
	_ "crypto/sha256"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEvidence_p1_sign_and_verify(t *testing.T) {
	tokenSigner := signerFromJWK(t, testECKeyA)

	var EvidenceIn Evidence

	err := EvidenceIn.SetClaims(mustBuildValidP1Claims(t, true, false))
	assert.NoError(t, err)

	cwt, err := EvidenceIn.ValidateAndSign(tokenSigner)
	assert.NoError(t, err, "signing failed")

	fmt.Printf("PSA evidence (profile 1): %x\n", cwt)

	EvidenceOut, err := DecodeAndValidateEvidenceFromCOSE(cwt)
	assert.NoError(t, err, "Sign1Message decoding failed")

	pk := pubKeyFromJWK(t, testECKeyA)

	err = EvidenceOut.Verify(pk)
	assert.NoError(t, err, "signature verification failed: verification error")
}

func TestEvidence_p2_sign_and_verify(t *testing.T) {
	tokenSigner := signerFromJWK(t, testECKeyA)

	var EvidenceIn Evidence

	err := EvidenceIn.SetClaims(mustBuildValidP2Claims(t, true))
	assert.NoError(t, err)

	cwt, err := EvidenceIn.ValidateAndSign(tokenSigner)
	assert.NoError(t, err, "signing failed")

	fmt.Printf("PSA evidence (profile 2): %x\n", cwt)

	EvidenceOut, err := DecodeAndValidateEvidenceFromCOSE(cwt)
	assert.NoError(t, err, "Sign1Message decoding failed")

	pk := pubKeyFromJWK(t, testECKeyA)

	err = EvidenceOut.Verify(pk)
	assert.NoError(t, err, "verification failed")
}

func TestEvidence_p2_TFM_verify(t *testing.T) {
	tfmP2Sign1 := `
d28443a10126a05901caaa0a584000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000
00000000000000000000000000000000000019095d5820a0a1a2a3a4a5a6
a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf1901005821
01fa58755f658627ce5460f29b75296713248cae7ad9e2984b90280efcbc
b5024819095c5820aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbcccccccccccc
ccccdddddddddddddddd19095a190bba19095b19300019095f82a5016353
50450465312e362e30055820bfe6d86f8826f4ff97fb96c4e6fbc4993e46
19fc565da26adf34c329489adc38066653484132353602582096a2ec56c6
5120a60ce3a53ef8d2082233772aacd5b17935a92be12ac577f685a50164
4e5350450465302e302e30055820b360caf5c98c6b942a4882fa9d4823ef
b166a9ef6a6e4aa37c1919ed1fccc0490666534841323536025820087d13
c68f32aaafb8c4fc0a2253445432009765e216fb85c398c9580522c1bf19
0960777777772e747275737465646669726d776172652e6f726719010978
18687474703a2f2f61726d2e636f6d2f7073612f322e302e3019095e7330
3630343536353237323832392d31303031305840b7617c38294b0e78bf92
b593749c6c40721371b06a8a02494fa4ad7b1508104a7d67243ccd78c4ae
b4016b312cc90fa0d629909eda28ed28013dfc71d8d33271
`
	cwt := mustHexDecode(t, tfmP2Sign1)

	e, err := DecodeAndValidateEvidenceFromCOSE(cwt)
	assert.NoError(t, err, "Sign1Message decoding failed")

	pk := pubKeyFromJWK(t, testTFMECKey)

	err = e.Verify(pk)
	assert.NoError(t, err, "verification failed")
}

func TestEvidence_p1_TFM_verify(t *testing.T) {
	tfmP1Sign1 := `
d28443a10126a05901d8aa3a000124ff5840000000000000000000000000
000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000003a000124fb5820a0
a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbe
bf3a00012500582101fa58755f658627ce5460f29b75296713248cae7ad9
e2984b90280efcbcb502483a000124fa5820aaaaaaaaaaaaaaaabbbbbbbb
bbbbbbbbccccccccccccccccdddddddddddddddd3a000124f8190bba3a00
0124f91930003a000124fd82a501635350450465312e362e30055820bfe6
d86f8826f4ff97fb96c4e6fbc4993e4619fc565da26adf34c329489adc38
066653484132353602582081e265884997ccc4fbb37738b99842bd6408da
e6a02b4db709b1ac198840f05aa501644e5350450465302e302e30055820
b360caf5c98c6b942a4882fa9d4823efb166a9ef6a6e4aa37c1919ed1fcc
c0490666534841323536025820087d13c68f32aaafb8c4fc0a2253445432
009765e216fb85c398c9580522c1bf3a00012501777777772e7472757374
65646669726d776172652e6f72673a000124f7715053415f494f545f5052
4f46494c455f313a000124fc73303630343536353237323832392d313030
31305840b7617c38294b0e78bf92b593749c6c40721371b06a8a02494fa4
ad7b1508104a6314781f12a16222f7d48bb8e953dd23153d9ebdbe8a433a
e7f48a5eead228c5
`
	cwt := mustHexDecode(t, tfmP1Sign1)

	e, err := DecodeAndValidateEvidenceFromCOSE(cwt)
	assert.NoError(t, err, "Sign1Message decoding failed")

	pk := pubKeyFromJWK(t, testTFMECKey)

	err = e.Verify(pk)
	assert.NoError(t, err, "verification failed")
}

func TestEvidence_FromCOSE_cwt_is_not_cose_sign1(t *testing.T) {
	e := Evidence{}

	err := e.UnmarshalCOSE([]byte{0x00})

	assert.EqualError(t, err, "failed CBOR decoding for CWT: cbor: invalid COSE_Sign1_Tagged object")
}

func TestEvidence_FromCOSE_empty_message(t *testing.T) {
	tv := []byte{
		0xd2, 0x84,
	}

	e := Evidence{}

	err := e.UnmarshalCOSE(tv)

	assert.EqualError(t, err, "failed CBOR decoding for CWT: unexpected EOF")
}

func TestEvidence_FromCOSE_empty_claims(t *testing.T) {
	tv := []byte{
		0xd2, 0x84, 0x43, 0xa1, 0x01, 0x26, 0xa0, 0x40, 0x44, 0xde, 0xad,
		0xbe, 0xef,
	}

	e := Evidence{}

	err := e.UnmarshalCOSE(tv)

	expectedErr := `failed CBOR decoding of PSA claims: EOF`

	assert.EqualError(t, err, expectedErr)
}

func TestEvidence_FromCOSE_bad_claims_unknown_profile(t *testing.T) {
	// 18([<< {1: -7} >>, {}, << {265: "http://arm.com/psa/3.0.0"} >>, h'DEADBEEF'])
	tv := []byte{
		0xd2, 0x84, 0x43, 0xa1, 0x01, 0x26, 0xa0, 0x58, 0x1e, 0xa1, 0x19, 0x01,
		0x09, 0x78, 0x18, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x61, 0x72,
		0x6d, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x70, 0x73, 0x61, 0x2f, 0x33, 0x2e,
		0x30, 0x2e, 0x30, 0x44, 0xde, 0xad, 0xbe, 0xef,
	}
	expectedErr := `failed CBOR decoding of PSA claims: unknown profile: "http://arm.com/psa/3.0.0"`

	_, err := DecodeAndValidateEvidenceFromCOSE(tv)

	assert.EqualError(t, err, expectedErr)
}

func TestEvidence_FromUnvalidatedCOSE(t *testing.T) {
	type TestVector struct {
		data        []byte
		expectedErr string
	}

	testVectors := []TestVector{
		{[]byte{0x00}, "failed CBOR decoding for CWT: cbor: invalid COSE_Sign1_Tagged object"},
		{[]byte{0xd2, 0x84}, "failed CBOR decoding for CWT: unexpected EOF"},
		{[]byte{
			0xd2, 0x84, 0x43, 0xa1, 0x01, 0x26, 0xa0, 0x40, 0x44, 0xde, 0xad,
			0xbe, 0xef,
		}, `failed CBOR decoding of PSA claims: EOF`},
		{[]byte{
			0xd2, 0x84, 0x43, 0xa1, 0x01, 0x26, 0xa0, 0x58, 0x1e, 0xa1, 0x19, 0x01,
			0x09, 0x78, 0x18, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x61, 0x72,
			0x6d, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x70, 0x73, 0x61, 0x2f, 0x33, 0x2e,
			0x30, 0x2e, 0x30, 0x44, 0xde, 0xad, 0xbe, 0xef,
		}, `failed CBOR decoding of PSA claims: unknown profile: "http://arm.com/psa/3.0.0"`},
		{[]byte{
			0xd2, 0x84, 0x43, 0xa1, 0x01, 0x26, 0xa0, 0x58, 0x1e, 0xa1, 0x19, 0x01,
			0x09, 0x78, 0x18, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x61, 0x72,
			0x6d, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x70, 0x73, 0x61, 0x2f, 0x32, 0x2e,
			0x30, 0x2e, 0x30, 0x44, 0xde, 0xad, 0xbe, 0xef,
		}, ``},
	}

	e := Evidence{}
	for _, tv := range testVectors {
		err := e.UnmarshalCOSE(tv.data)
		if tv.expectedErr == "" {
			assert.NoError(t, err)
		} else {
			assert.EqualError(t, err, tv.expectedErr)
		}
	}
}

func TestEvidence_SetClaims_unknown_profile(t *testing.T) {
	evidence := Evidence{}
	emptyClaims := &P1Claims{}

	err := evidence.SetClaims(emptyClaims)

	assert.EqualError(t, err, "validation failed: validating security lifecycle: missing mandatory claim")
}

func TestEvidence_SetClaims_validation_failed(t *testing.T) {
	tv := newP2Claims()

	evidence := Evidence{}

	err := evidence.SetClaims(tv)

	assert.EqualError(t, err, "validation failed: validating security lifecycle: missing mandatory claim")
}

func TestEvidence_SetClaims_ok(t *testing.T) {
	tv := mustBuildValidP2Claims(t, false)

	evidence := Evidence{}

	err := evidence.SetClaims(tv)

	assert.NoError(t, err)
}

func TestEvidence_GetInstanceID_psa_profile_2_ok(t *testing.T) {
	tv := mustBuildValidP2Claims(t, false)

	evidence := Evidence{}
	err := evidence.SetClaims(tv)
	require.NoError(t, err)

	expected := &testInstID

	actual := evidence.GetInstanceID()
	assert.Equal(t, expected, actual)
}

func TestEvidence_GetImplementationID_psa_profile_2_ok(t *testing.T) {
	tv := mustBuildValidP2Claims(t, false)

	evidence := Evidence{}
	err := evidence.SetClaims(tv)
	require.NoError(t, err)

	expected := &testImplementationID

	actual := evidence.GetImplementationID()
	assert.Equal(t, expected, actual)
}

func TestEvidence_Verify_no_message(t *testing.T) {
	evidence := Evidence{}
	var pk crypto.PublicKey

	err := evidence.Verify(pk)
	assert.EqualError(t, err, "no Sign1 message found")
}

func TestEvidence_sign_and_verify_key_mismatch(t *testing.T) {
	tokenSigner := signerFromJWK(t, testECKeyA)

	var EvidenceIn Evidence

	err := EvidenceIn.SetClaims(mustBuildValidP2Claims(t, true))
	assert.NoError(t, err)

	cwt, err := EvidenceIn.ValidateAndSign(tokenSigner)
	assert.NoError(t, err, "signing failed")

	fmt.Printf("PSA evidence (profile 2): %x\n", cwt)

	EvidenceOut, err := DecodeAndValidateEvidenceFromCOSE(cwt)
	assert.NoError(t, err, "Sign1Message decoding failed")

	pk := pubKeyFromJWK(t, testTFMECKey)
	err = EvidenceOut.Verify(pk)
	assert.EqualError(t, err, "signature verification failed: verification error")
}

func TestEvidence_sign_and_verify_alg_mismatch(t *testing.T) {
	tokenSigner := signerFromJWK(t, testECKeyA)

	var EvidenceIn Evidence

	err := EvidenceIn.SetClaims(mustBuildValidP2Claims(t, true))
	assert.NoError(t, err)

	cwt, err := EvidenceIn.ValidateAndSign(tokenSigner)
	assert.NoError(t, err, "signing failed")

	fmt.Printf("PSA evidence (profile 2): %x\n", cwt)

	EvidenceOut, err := DecodeAndValidateEvidenceFromCOSE(cwt)
	assert.NoError(t, err, "Sign1Message decoding failed")

	var pk crypto.PublicKey

	err = EvidenceOut.Verify(pk)
	assert.EqualError(t, err, "unable to instantiate verifier: ES256: algorithm mismatch")
}

func TestEvidence_SignUnvalidated(t *testing.T) {
	tokenSigner := signerFromJWK(t, testECKeyA)

	buf := mustHexDecode(t, testEncodedP2ClaimsMissingMandatoryNonce)
	v, err := DecodeClaimsFromCBOR(buf)
	require.NoError(t, err)

	var EvidenceIn Evidence

	EvidenceIn.Claims = v

	cwt, err := EvidenceIn.Sign(tokenSigner)
	assert.NoError(t, err, "signing failed")

	fmt.Printf("PSA evidence (profile 2): %x\n", cwt)

	EvidenceOut, err := DecodeEvidenceFromCOSE(cwt)
	assert.NoError(t, err, "Sign1Message decoding failed")

	pk := pubKeyFromJWK(t, testTFMECKey)
	err = EvidenceOut.Verify(pk)
	assert.EqualError(t, err, "signature verification failed: verification error")
}
