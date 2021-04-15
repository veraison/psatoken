// Copyright 2021 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package psatoken

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	_ "crypto/sha256"
	"reflect"
	"testing"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/eat"
	cose "github.com/veraison/go-cose"
)

func signerFromJWK(t *testing.T, j string) *cose.Signer {
	ks, err := jwk.ParseString(j)
	require.Nil(t, err)

	var key crypto.PrivateKey

	err = ks.Keys[0].Raw(&key)
	require.Nil(t, err)

	var crv elliptic.Curve
	var alg *cose.Algorithm

	switch v := key.(type) {
	case *ecdsa.PrivateKey:
		crv = v.Curve
		if crv == elliptic.P256() {
			alg = cose.ES256
			break
		}
		require.True(t, false, "unknown elliptic curve %v", crv)
	default:
		require.True(t, false, "unknown private key type %v", reflect.TypeOf(key))
	}

	s, err := cose.NewSignerFromKey(alg, key)
	require.Nil(t, err)

	return s
}

func TestEvidence_sign_and_verify(t *testing.T) {
	var ECKey = `{
  "kty": "EC",
  "crv": "P-256",
  "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
  "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
  "d": "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
  "use": "enc",
  "kid": "1"
}`
	tokenSigner := signerFromJWK(t, ECKey)

	var EvidenceIn Evidence

	EvidenceIn.Claims = makeClaims(t)

	cwt, err := EvidenceIn.Sign(tokenSigner)
	assert.Nil(t, err, "signing failed")

	var EvidenceOut Evidence

	err = EvidenceOut.FromCOSE(cwt, PSA_PROFILE_2)
	assert.Nil(t, err, "Sign1Message decoding failed")

	err = EvidenceOut.Verify(tokenSigner.Verifier().PublicKey)
	assert.Nil(t, err, "verification failed")
}

func TestEvidence_FromCOSE_unknown_supported_profile(t *testing.T) {
	e := Evidence{}

	err := e.FromCOSE([]byte{0x00}, "unknown_profile_1", "unknown_profile_2")

	assert.EqualError(t, err, "none of the requested profiles (unknown_profile_1, unknown_profile_2) is currently supported")
}

func TestEvidence_FromCOSE_empty_supported_profile(t *testing.T) {
	e := Evidence{}

	err := e.FromCOSE([]byte{0x00})

	assert.EqualError(t, err, "no profile supplied")
}

func TestEvidence_FromCOSE_cwt_is_not_cose_sign1(t *testing.T) {
	e := Evidence{}

	err := e.FromCOSE([]byte{0x00}, PSA_PROFILE_2)

	assert.EqualError(t, err, "the supplied CWT is not a COSE-Sign1 message")
}

func TestEvidence_FromCOSE_empty_message(t *testing.T) {
	tv := []byte{
		0xd2, 0x84,
	}

	e := Evidence{}

	err := e.FromCOSE(tv, PSA_PROFILE_2, PSA_PROFILE_1)

	assert.EqualError(t, err, "failed CBOR decoding for CWT: unexpected EOF")
}

func TestEvidence_FromCOSE_empty_claims(t *testing.T) {
	tv := []byte{
		0xd2, 0x84, 0x43, 0xa1, 0x01, 0x26, 0xa0, 0x40, 0x44, 0xde, 0xad,
		0xbe, 0xef,
	}

	e := Evidence{}

	err := e.FromCOSE(tv, PSA_PROFILE_2, PSA_PROFILE_1)

	assert.EqualError(t, err, "failed CBOR decoding of PSA claims: EOF")
}

func TestEvidence_FromCOSE_bad_claims_unknown_profile(t *testing.T) {
	tv := []byte{
		0xd2, 0x84, 0x43, 0xa1, 0x01, 0x26, 0xa0, 0x58, 0x1c, 0xa1, 0x12,
		0x78, 0x18, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x61, 0x72,
		0x6d, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x70, 0x73, 0x61, 0x2f, 0x33,
		0x2e, 0x30, 0x2e, 0x30, 0x44, 0xde, 0xad, 0xbe, 0xef,
	}

	e := Evidence{}

	err := e.FromCOSE(tv, PSA_PROFILE_2, PSA_PROFILE_1)

	assert.EqualError(t, err, "claims validation failed: profile claim missing")
}

func TestEvidence_SetClaims_unknown_profile(t *testing.T) {
	tv := &Claims{}

	evidence := Evidence{}

	err := evidence.SetClaims(tv, "UNKNOWN_PROFILE_3")

	assert.EqualError(t, err, "none of the requested profiles (UNKNOWN_PROFILE_3) is currently supported")
}

func TestEvidence_SetClaims_validation_failed(t *testing.T) {
	profile, err := eat.NewProfile(PSA_PROFILE_2)
	require.Nil(t, err)

	tv := Claims{
		Profile: profile,
	}

	evidence := Evidence{}

	err = evidence.SetClaims(&tv, PSA_PROFILE_2)

	assert.EqualError(t, err, "validation failed: missing mandatory partition-id")
}

func TestEvidence_SetClaims_ok(t *testing.T) {
	tv := makeClaims(t)

	evidence := Evidence{}

	err := evidence.SetClaims(&tv, PSA_PROFILE_2)

	assert.Nil(t, err)
}

func TestEvidence_GetInstanceID_psa_profile_2_ok(t *testing.T) {
	tv := makeClaims(t)

	evidence := Evidence{}

	expected := (*[]byte)(testInstID)

	err := evidence.SetClaims(&tv, PSA_PROFILE_2)
	require.Nil(t, err)

	actual := evidence.GetInstanceID()
	assert.Equal(t, expected, actual)
}

func TestEvidence_GetInstanceID_psa_profile_1_fail(t *testing.T) {
	claims := makeClaims(t)

	// move InstanceID to legacy (dodgy move!)
	claims.LegacyInstID = (*[]byte)(claims.InstID)
	claims.InstID = nil

	evidence := Evidence{
		Claims: claims,
	}

	actual := evidence.GetInstanceID()
	assert.Nil(t, actual)
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
