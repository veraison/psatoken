// Copyright 2021-2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package psatoken

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"testing"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	cose "github.com/veraison/go-cose"
)

var (
	testECKeyA = `{
  "kty": "EC",
  "crv": "P-256",
  "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
  "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
  "d": "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"
}`
	testECKeyB = `{
  "kty": "EC",
  "crv": "P-256",
  "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqx7D4",
  "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
  "d": "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"
}`
	testTFMECKey = `{
  "kty": "EC",
  "crv": "P-256",
  "x": "eeupDov0UKZ1FXatRZmwet-TjaO7C9F9ADbtSaLQ_D8",
  "y": "v836iVa1aL_bhnPmSNi1jZKZVbFKJsMIDzQRfZcdaGQ",
  "d": "qbRUsm1vkKTqMRk1ZMupH-xvmgAqfcBQS5Khk3E0WF8"
 }`
	testNotJSON                  = []byte(`{`)
	testNotCBOR                  = `6e6f745f63626f720a`
	testClientIDSPE              = int32(2147483647)
	testSecurityLifecycleSecured = uint16(SecurityLifecycleSecuredMin)
	testCcaLifeCycleSecured      = uint16(12288)
	testConfig                   = []byte{1, 2, 3}
	testHashAlgID                = "sha-256"
	testImplementationID         = []byte{
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
	}
	testBootSeedMin = []byte{
		0, 0, 0, 0, 0, 0, 0, 0,
	}
	testBootSeed = []byte{
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
	}
	testCertificationReferenceP1 = "1234567890123"
	testCertificationReferenceP2 = "1234567890123-12345"
	testNonce                    = []byte{
		1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1,
	}
	testInstID = []byte{
		0x01, // RAND
		2, 2, 2, 2, 2, 2, 2, 2,
		2, 2, 2, 2, 2, 2, 2, 2,
		2, 2, 2, 2, 2, 2, 2, 2,
		2, 2, 2, 2, 2, 2, 2, 2,
	}
	testVSI              = "https://veraison.example/v1/challenge-response"
	testMeasurementValue = []byte{
		3, 3, 3, 3, 3, 3, 3, 3,
		3, 3, 3, 3, 3, 3, 3, 3,
		3, 3, 3, 3, 3, 3, 3, 3,
		3, 3, 3, 3, 3, 3, 3, 3,
	}
	testSignerID = []byte{
		4, 4, 4, 4, 4, 4, 4, 4,
		4, 4, 4, 4, 4, 4, 4, 4,
		4, 4, 4, 4, 4, 4, 4, 4,
		4, 4, 4, 4, 4, 4, 4, 4,
	}
	testSoftwareComponents = []SwComponent{
		{
			MeasurementValue: &testMeasurementValue,
			SignerID:         &testSignerID,
		},
	}
)

func mustHexDecode(t *testing.T, s string) []byte {
	// support CBOR-diag "pretty" format:
	// * allow long hex string to be split over multiple lines (with soft or
	//   hard tab indentation)
	// * allow comments starting with '#' up to the NL
	comments := regexp.MustCompile("#.*\n")
	emptiness := regexp.MustCompile("[ \t\n]")

	s = comments.ReplaceAllString(s, "")
	s = emptiness.ReplaceAllString(s, "")

	data, err := hex.DecodeString(s)
	if t != nil {
		require.NoError(t, err)
	} else if err != nil {
		panic(err)
	}
	return data
}

// Load JSON test vector without running the PSA token validation logics so
// that we can pass in bogus data.
func loadJSONTestVectorFromFile(fn string, profile string) (IClaims, error) {
	buf, err := os.ReadFile(fn)
	if err != nil {
		return nil, err
	}

	var p IClaims

	switch profile {
	case PsaProfile1:
		p = &P1Claims{}
	case PsaProfile2:
		p = &P2Claims{}
	}

	err = json.Unmarshal(buf, p)
	if err != nil {
		return nil, err
	}

	return p, nil
}

func signerFromJWK(t *testing.T, j string) cose.Signer {
	alg, key := getAlgAndKeyFromJWK(t, j)
	s, err := cose.NewSigner(alg, key)
	require.Nil(t, err)

	return s
}

func getAlgAndKeyFromJWK(t *testing.T, j string) (cose.Algorithm, crypto.Signer) {
	ks, err := jwk.ParseString(j)
	require.Nil(t, err)

	var (
		key crypto.Signer
		crv elliptic.Curve
		alg cose.Algorithm
	)

	k, ok := ks.Get(0)
	require.True(t, ok)
	err = k.Raw(&key)
	require.NoError(t, err)

	switch v := key.(type) {
	case *ecdsa.PrivateKey:
		crv = v.Curve
		if crv == elliptic.P256() {
			alg = cose.AlgorithmES256
			break
		}
		require.True(t, false, "unknown elliptic curve %v", crv)
	default:
		require.True(t, false, "unknown private key type %v", reflect.TypeOf(key))
	}
	return alg, key
}

func pubKeyFromJWK(t *testing.T, j string) crypto.PublicKey {
	_, key := getAlgAndKeyFromJWK(t, j)
	vk := key.Public()
	return vk
}

func validateNegatives(t *testing.T, profile string) {
	type tCase struct {
		fPath  string
		eStr   string
		p2Only bool
		p1Only bool
	}

	tCases := []tCase{
		// 0
		{
			fPath: "testvectors/json/test-profile-invalid-unknown.json",
			eStr:  fmt.Sprintf(`wrong profile: expecting %q, got "http://UNKNOWN"`, profile),
		},
		// 1
		{
			fPath: "testvectors/json/test-client-id-invalid-missing.json",
			eStr:  `validating psa-client-id: missing mandatory claim`,
		},
		// 2
		{
			fPath: "testvectors/json/test-security-lifecycle-invalid-missing.json",
			eStr:  `validating psa-security-lifecycle: missing mandatory claim`,
		},
		// 3
		{
			fPath: "testvectors/json/test-security-lifecycle-invalid-state.json",
			eStr:  `validating psa-security-lifecycle: wrong syntax for claim: value 65535 is invalid`,
		},
		// 4
		{
			fPath: "testvectors/json/test-implementation-id-invalid-missing.json",
			eStr:  `validating psa-implementation-id: missing mandatory claim`,
		},
		// 5
		{
			fPath: "testvectors/json/test-implementation-id-invalid-short.json",
			eStr:  `validating psa-implementation-id: wrong syntax for claim: invalid length 4 (MUST be 32 bytes)`,
		},
		// 6
		{
			fPath: "testvectors/json/test-implementation-id-invalid-long.json",
			eStr:  `validating psa-implementation-id: wrong syntax for claim: invalid length 34 (MUST be 32 bytes)`,
		},
		// 7
		{
			fPath: "testvectors/json/test-sw-components-invalid-missing.json",
			eStr:  `validating psa-software-components: missing mandatory claim`,
		},
		// 8
		{
			fPath:  "testvectors/json/test-boot-seed-invalid-short.json",
			eStr:   `validating psa-boot-seed: wrong syntax for claim: invalid length 4 (MUST be 32 bytes)`,
			p1Only: true,
		},
		// 9
		{
			fPath:  "testvectors/json/test-boot-seed-invalid-long.json",
			eStr:   `validating psa-boot-seed: wrong syntax for claim: invalid length 34 (MUST be 32 bytes)`,
			p1Only: true,
		},
		// 10
		{
			fPath: "testvectors/json/test-hardware-version-invalid.json",
			eStr:  `validating psa-certification-reference: wrong syntax for claim: MUST be in EAN-13`,
		},
		// 11
		{
			fPath: "testvectors/json/test-nonce-invalid-missing.json",
			eStr:  `validating psa-nonce: missing mandatory claim`,
		},
		// 12
		{
			fPath: "testvectors/json/test-nonce-invalid-short.json",
			eStr:  `validating psa-nonce: wrong syntax for claim: length 4 (psa-hash-type MUST be 32, 48 or 64 bytes)`,
		},
		// 13
		{
			fPath: "testvectors/json/test-nonce-invalid-long.json",
			eStr:  `validating psa-nonce: wrong syntax for claim: length 65 (psa-hash-type MUST be 32, 48 or 64 bytes)`,
		},
		// 14
		{
			fPath: "testvectors/json/test-instance-id-invalid-missing.json",
			eStr:  `validating psa-instance-id: missing mandatory claim`,
		},
		// 15
		{
			fPath: "testvectors/json/test-instance-id-invalid-short.json",
			eStr:  `validating psa-instance-id: wrong syntax for claim: invalid length 32 (MUST be 33 bytes)`,
		},
		// 16
		{
			fPath: "testvectors/json/test-instance-id-invalid-long.json",
			eStr:  `validating psa-instance-id: wrong syntax for claim: invalid length 34 (MUST be 33 bytes)`,
		},
		// 17
		{
			fPath: "testvectors/json/test-sw-component-measurement-value-invalid-missing.json",
			eStr:  `validating psa-software-components: failed at index 0: missing mandatory measurement-value`,
		},
		// 18
		{
			fPath: "testvectors/json/test-sw-component-signer-id-invalid-missing.json",
			eStr:  `validating psa-software-components: failed at index 1: missing mandatory signer-id`,
		},
		// 19
		{
			fPath: "testvectors/json/test-sw-component-measurement-value-invalid-short.json",
			// nolint:lll
			eStr: `validating psa-software-components: failed at index 0: invalid measurement-value: wrong syntax for claim: length 4 (psa-hash-type MUST be 32, 48 or 64 bytes)`,
		},
		// 20
		{
			fPath: "testvectors/json/test-sw-component-signer-id-invalid-short.json",
			// nolint:lll
			eStr: `validating psa-software-components: failed at index 1: invalid signer-id: wrong syntax for claim: length 4 (psa-hash-type MUST be 32, 48 or 64 bytes)`,
		},
		// 21
		{
			fPath: "testvectors/json/test-instance-id-invalid-euid-type.json",
			eStr:  `validating psa-instance-id: wrong syntax for claim: invalid EUID type (MUST be RAND=0x01)`,
		},
		// 22
		{
			fPath: "testvectors/json/test-sw-component-and-no-sw-measurements-missing.json",
			eStr:  `validating psa-software-components: missing mandatory claim`,
		},
		// 23
		{
			fPath:  "testvectors/json/test-profile-invalid-missing.json",
			eStr:   `validating profile: missing mandatory claim`,
			p2Only: true,
		},
		// 24
		{
			fPath: "testvectors/json/test-sw-components-empty.json",
			eStr:  `validating psa-software-components: wrong syntax for claim: there MUST be at least one entry`,
		},
		// 25
		{
			fPath: "testvectors/json/test-sw-components-invalid-combo.json",
			// nolint:lll
			eStr:   `validating psa-software-components: wrong syntax for claim: psa-no-sw-measurement and psa-software-components cannot be present at the same time`,
			p1Only: true,
		},
		// 26
		{
			fPath: "testvectors/json/test-vsi-invalid-empty.json",
			eStr:  `validating psa-verification-service-indicator: wrong syntax for claim: empty string`,
		},
		// 27
		{
			fPath:  "testvectors/json/test-boot-seed-invalid-short.json",
			eStr:   `validating psa-boot-seed: wrong syntax for claim: invalid length 4 (MUST be between 8 and 32 bytes)`,
			p2Only: true,
		},
		// 28
		{
			fPath:  "testvectors/json/test-boot-seed-invalid-long.json",
			eStr:   `validating psa-boot-seed: wrong syntax for claim: invalid length 34 (MUST be between 8 and 32 bytes)`,
			p2Only: true,
		},
		// 29
		{
			fPath:  "testvectors/json/test-boot-seed-invalid-missing.json",
			eStr:   `validating psa-boot-seed: missing mandatory claim`,
			p1Only: true,
		},
	}

	for i, tc := range tCases {
		if profile != PsaProfile1 && tc.p1Only ||
			profile != PsaProfile2 && tc.p2Only {
			continue
		}

		p, err := loadJSONTestVectorFromFile(tc.fPath, profile)
		require.Nil(t, err, "unable to load %s: %v", tc.fPath, err)

		err = p.Validate()
		assert.ErrorContains(t, err, tc.eStr, "failed TCase at index %d (%s)", i, tc.fPath)
	}
}

func validatePositives(t *testing.T, profile string) {
	type tCase struct {
		fPath  string
		p1Only bool
		p2Only bool
	}

	tCases := []tCase{
		{
			fPath: "testvectors/json/test-token-valid-full.json",
		},
		{
			fPath:  "testvectors/json/test-token-valid-minimalist-p1.json",
			p1Only: true,
		},
		{
			fPath:  "testvectors/json/test-token-valid-minimalist-p2.json",
			p2Only: true,
		},
		{
			fPath:  "testvectors/json/test-token-valid-minimalist-no-sw-measurements.json",
			p1Only: true,
		},
		{
			fPath:  "testvectors/json/test-profile-valid-missing.json",
			p1Only: true,
		},
	}

	for i, tc := range tCases {
		if profile != PsaProfile1 && tc.p1Only ||
			profile != PsaProfile2 && tc.p2Only {
			continue
		}

		p, err := loadJSONTestVectorFromFile(tc.fPath, profile)
		require.Nil(t, err, "unable to load %s: %v", tc.fPath, err)

		err = p.Validate()
		assert.Nil(t, err, "failed TCase at index %d (%s)", i, tc.fPath)
	}
}
