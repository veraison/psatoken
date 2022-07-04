// Copyright 2021-2022 Contributors to the Veraison project.
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
	tokenSigner := signerFromJWK(t, ECKey)

	var EvidenceIn Evidence

	err := EvidenceIn.SetClaims(mustBuildValidP1Claims(t, true, false))
	assert.NoError(t, err)

	cwt, err := EvidenceIn.Sign(tokenSigner)
	assert.NoError(t, err, "signing failed")

	fmt.Printf("PSA evidence (profile 1): %x\n", cwt)

	var EvidenceOut Evidence

	err = EvidenceOut.FromCOSE(cwt)
	assert.NoError(t, err, "Sign1Message decoding failed")

	err = EvidenceOut.Verify(tokenSigner.Verifier().PublicKey)
	assert.NoError(t, err, "verification failed")
}

func TestEvidence_p2_sign_and_verify(t *testing.T) {
	tokenSigner := signerFromJWK(t, ECKey)

	var EvidenceIn Evidence

	err := EvidenceIn.SetClaims(mustBuildValidP2Claims(t, true))
	assert.NoError(t, err)

	cwt, err := EvidenceIn.Sign(tokenSigner)
	assert.NoError(t, err, "signing failed")

	fmt.Printf("PSA evidence (profile 2): %x\n", cwt)

	var EvidenceOut Evidence

	err = EvidenceOut.FromCOSE(cwt)
	assert.NoError(t, err, "Sign1Message decoding failed")

	err = EvidenceOut.Verify(tokenSigner.Verifier().PublicKey)
	assert.NoError(t, err, "verification failed")
}

func TestEvidence_FromCOSE_cwt_is_not_cose_sign1(t *testing.T) {
	e := Evidence{}

	err := e.FromCOSE([]byte{0x00})

	assert.EqualError(t, err, "the supplied CWT is not a COSE_Sign1 message")
}

func TestEvidence_FromCOSE_empty_message(t *testing.T) {
	tv := []byte{
		0xd2, 0x84,
	}

	e := Evidence{}

	err := e.FromCOSE(tv)

	assert.EqualError(t, err, "failed CBOR decoding for CWT: unexpected EOF")
}

func TestEvidence_FromCOSE_empty_claims(t *testing.T) {
	tv := []byte{
		0xd2, 0x84, 0x43, 0xa1, 0x01, 0x26, 0xa0, 0x40, 0x44, 0xde, 0xad,
		0xbe, 0xef,
	}

	e := Evidence{}

	err := e.FromCOSE(tv)

	expectedErr := `failed CBOR decoding of PSA claims: decode failed for both p1 (CBOR decoding of PSA claims failed: EOF) and p2 (CBOR decoding of PSA claims failed: EOF)`

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

	e := Evidence{}

	err := e.FromCOSE(tv)

	expectedErr := `failed CBOR decoding of PSA claims: decode failed for both p1 (validation of PSA claims failed: validating psa-client-id: missing mandatory claim) and p2 (validation of PSA claims failed: wrong profile: expecting "http://arm.com/psa/2.0.0", got "http://arm.com/psa/3.0.0")`

	assert.EqualError(t, err, expectedErr)
}

func TestEvidence_SetClaims_unknown_profile(t *testing.T) {
	evidence := Evidence{}
	emptyClaims := &P1Claims{}

	err := evidence.SetClaims(emptyClaims)

	assert.EqualError(t, err, "validation failed: validating psa-client-id: missing mandatory claim")
}

func TestEvidence_SetClaims_validation_failed(t *testing.T) {
	tv, err := newP2Claims()
	require.NoError(t, err)

	evidence := Evidence{}

	err = evidence.SetClaims(tv)

	assert.EqualError(t, err, "validation failed: validating psa-client-id: missing mandatory claim")
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

func TestEvidence_Sign_no_signer(t *testing.T) {
	evidence := Evidence{}

	_, err := evidence.Sign(nil)
	assert.EqualError(t, err, "nil signer")
}

func TestEvidence_Verify_no_message(t *testing.T) {
	evidence := Evidence{}
	var pk crypto.PublicKey

	err := evidence.Verify(pk)
	assert.EqualError(t, err, "no Sign1 message found")
}
