// Copyright 2021 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package psatoken

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	_ "crypto/sha256"
	"encoding/json"
	"io/ioutil"
	"reflect"
	"testing"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// Load JSON test vector without running the PSA token validation logics so
// that we can pass in bogus data.
func loadJSONTestVectorFromFile(fn string) (*Claims, error) {
	buf, err := ioutil.ReadFile(fn)
	if err != nil {
		return nil, err
	}

	p := &Claims{}
	err = json.Unmarshal(buf, p)
	if err != nil {
		return nil, err
	}

	return p, nil
}

func TestClaims_validate_positives(t *testing.T) {
	tCases := []string{
		"testvectors/test-token-valid-full.json",
		"testvectors/test-token-valid-minimalist.json",
		"testvectors/test-token-valid-full-no-swcomp.json",
	}

	for i, fPath := range tCases {
		p, err := loadJSONTestVectorFromFile(fPath)
		require.Nil(t, err, "unable to load %s: %v", fPath, err)

		err = p.validate()
		assert.Nil(t, err, "failed TCase at index %d (%s)", i, fPath)
	}
}

func TestClaims_validate_negatives(t *testing.T) {
	type TCase struct {
		fPath string
		eStr  string
	}

	tCases := []TCase{
		// 0
		{
			fPath: "testvectors/test-profile-invalid-unknown.json",
			eStr:  "unknown profile 'UNKNOWN' (MUST be 'PSA_IOT_PROFILE_1')",
		},
		// 1
		{
			fPath: "testvectors/test-client-id-invalid-missing.json",
			eStr:  "missing mandatory partition-id",
		},
		// 2
		{
			fPath: "testvectors/test-security-lifecycle-invalid-missing.json",
			eStr:  "missing mandatory security-life-cycle",
		},
		// 3
		{
			fPath: "testvectors/test-security-lifecycle-invalid-state.json",
			eStr:  "unaccepted state: invalid/65535 (MUST be 'secured' or 'non-psa-rot-debug')",
		},
		// 4
		{
			fPath: "testvectors/test-implementation-id-invalid-missing.json",
			eStr:  "missing mandatory implementation-id",
		},
		// 5
		{
			fPath: "testvectors/test-implementation-id-invalid-short.json",
			eStr:  "invalid implementation-id length 4 (MUST be 32 bytes)",
		},
		// 6
		{
			fPath: "testvectors/test-implementation-id-invalid-long.json",
			eStr:  "invalid implementation-id length 34 (MUST be 32 bytes)",
		},
		// 7
		{
			fPath: "testvectors/test-boot-seed-invalid-missing.json",
			eStr:  "missing mandatory boot-seed",
		},
		// 8
		{
			fPath: "testvectors/test-boot-seed-invalid-short.json",
			eStr:  "invalid boot-seed length 4 (MUST be 32 bytes)",
		},
		// 9
		{
			fPath: "testvectors/test-boot-seed-invalid-long.json",
			eStr:  "invalid boot-seed length 34 (MUST be 32 bytes)",
		},
		// 10
		{
			fPath: "testvectors/test-hardware-version-invalid.json",
			eStr:  "invalid hardware-version format: MUST be GDSII",
		},
		// 11
		{
			fPath: "testvectors/test-nonce-invalid-missing.json",
			eStr:  "missing mandatory nonce",
		},
		// 12
		{
			fPath: "testvectors/test-nonce-invalid-short.json",
			eStr:  "invalid nonce length 4 (psa-hash-type MUST be 32, 48 or 64 bytes)",
		},
		// 13
		{
			fPath: "testvectors/test-nonce-invalid-long.json",
			eStr:  "invalid nonce length 65 (psa-hash-type MUST be 32, 48 or 64 bytes)",
		},
		// 14
		{
			fPath: "testvectors/test-instance-id-invalid-missing.json",
			eStr:  "missing mandatory instance-id",
		},
		// 15
		{
			fPath: "testvectors/test-instance-id-invalid-short.json",
			eStr:  "invalid instance-id length 32 (MUST be 33 bytes)",
		},
		// 16
		{
			fPath: "testvectors/test-instance-id-invalid-long.json",
			eStr:  "invalid instance-id length 34 (MUST be 33 bytes)",
		},
		// 17
		{
			fPath: "testvectors/test-sw-component-measurement-value-invalid-missing.json",
			eStr:  "invalid software-component[0]: missing mandatory measurement-value",
		},
		// 18
		{
			fPath: "testvectors/test-sw-component-signer-id-invalid-missing.json",
			eStr:  "invalid software-component[1]: missing mandatory signer-id",
		},
		// 19
		{
			fPath: "testvectors/test-sw-components-invalid-combo.json",
			eStr:  "no-software-measurements and software-components are mutually exclusive",
		},
		// 20
		{
			fPath: "testvectors/test-sw-component-measurement-value-invalid-short.json",
			eStr:  "invalid software-component[0]: invalid measurement-value length 4 (psa-hash-type MUST be 32, 48 or 64 bytes)",
		},
		// 21
		{
			fPath: "testvectors/test-sw-component-signer-id-invalid-short.json",
			eStr:  "invalid software-component[1]: invalid signer-id length 4 (psa-hash-type MUST be 32, 48 or 64 bytes)",
		},
		// 22
		{
			fPath: "testvectors/test-instance-id-invalid-euid-type.json",
			eStr:  "invalid instance-id EUID type (MUST be RAND=0x01)",
		},
		// 23
		{
			fPath: "testvectors/test-sw-component-and-no-sw-measurements-missing.json",
			eStr:  "no software-components found",
		},
	}

	for i, tc := range tCases {
		p, err := loadJSONTestVectorFromFile(tc.fPath)
		require.Nil(t, err, "unable to load %s: %v", tc.fPath, err)

		err = p.validate()
		assert.EqualError(t, err, tc.eStr, "failed TCase at index %d (%s)", i, tc.fPath)
	}
}

func TestClaims_ToCBOR_ok(t *testing.T) {
	tv := makeClaims()

	// AA                                      # map(10)
	//    3A 000124F7                          # negative(74999)
	//    71                                   # text(17)
	//       5053415F494F545F50524F46494C455F31 # "PSA_IOT_PROFILE_1"
	//    3A 000124F8                          # negative(75000)
	//    01                                   # unsigned(1)
	//    3A 000124F9                          # negative(75001)
	//    19 3000                              # unsigned(12288)
	//    3A 000124FA                          # negative(75002)
	//    58 20                                # bytes(32)
	//       5051525354555657505152535455565750515253545556575051525354555657
	//    3A 000124FB                          # negative(75003)
	//    58 20                                # bytes(32)
	//       DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF
	//    3A 000124FC                          # negative(75004)
	//    6D                                   # text(13)
	//       31323334353637383930313233        # "1234567890123"
	//    3A 000124FD                          # negative(75005)
	//    82                                   # array(2)
	//       A3                                # map(3)
	//          01                             # unsigned(1)
	//          62                             # text(2)
	//             424C                        # "BL"
	//          02                             # unsigned(2)
	//          58 20                          # bytes(32)
	//             0001020400010204000102040001020400010204000102040001020400010204
	//          05                             # unsigned(5)
	//          58 20                          # bytes(32)
	//             519200FF519200FF519200FF519200FF519200FF519200FF519200FF519200FF
	//       A3                                # map(3)
	//          01                             # unsigned(1)
	//          64                             # text(4)
	//             50526F54                    # "PRoT"
	//          02                             # unsigned(2)
	//          58 20                          # bytes(32)
	//             0506070805060708050607080506070805060708050607080506070805060708
	//          05                             # unsigned(5)
	//          58 20                          # bytes(32)
	//             519200FF519200FF519200FF519200FF519200FF519200FF519200FF519200FF
	//    3A 000124FF                          # negative(75007)
	//    58 20                                # bytes(32)
	//       0001020300010203000102030001020300010203000102030001020300010203
	//    3A 00012500                          # negative(75008)
	//    58 21                                # bytes(33)
	//       01A0A1A2A3A0A1A2A3A0A1A2A3A0A1A2A3A0A1A2A3A0A1A2A3A0A1A2A3A0A1A2A3
	//    3A 00012501                          # negative(75009)
	//    78 18                                # text(24)
	//       68747470733A2F2F7073612D76657269666965722E6F7267 # "https://psa-verifier.org"
	//
	expected := []byte{
		0xaa, 0x3a, 0x00, 0x01, 0x24, 0xf7, 0x71, 0x50, 0x53, 0x41, 0x5f, 0x49,
		0x4f, 0x54, 0x5f, 0x50, 0x52, 0x4f, 0x46, 0x49, 0x4c, 0x45, 0x5f, 0x31,
		0x3a, 0x00, 0x01, 0x24, 0xf8, 0x01, 0x3a, 0x00, 0x01, 0x24, 0xf9, 0x19,
		0x30, 0x00, 0x3a, 0x00, 0x01, 0x24, 0xfa, 0x58, 0x20, 0x50, 0x51, 0x52,
		0x53, 0x54, 0x55, 0x56, 0x57, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56,
		0x57, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x50, 0x51, 0x52,
		0x53, 0x54, 0x55, 0x56, 0x57, 0x3a, 0x00, 0x01, 0x24, 0xfb, 0x58, 0x20,
		0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
		0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
		0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0x3a, 0x00, 0x01, 0x24,
		0xfc, 0x6d, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
		0x31, 0x32, 0x33, 0x3a, 0x00, 0x01, 0x24, 0xfd, 0x82, 0xa3, 0x01, 0x62,
		0x42, 0x4c, 0x02, 0x58, 0x20, 0x00, 0x01, 0x02, 0x04, 0x00, 0x01, 0x02,
		0x04, 0x00, 0x01, 0x02, 0x04, 0x00, 0x01, 0x02, 0x04, 0x00, 0x01, 0x02,
		0x04, 0x00, 0x01, 0x02, 0x04, 0x00, 0x01, 0x02, 0x04, 0x00, 0x01, 0x02,
		0x04, 0x05, 0x58, 0x20, 0x51, 0x92, 0x00, 0xff, 0x51, 0x92, 0x00, 0xff,
		0x51, 0x92, 0x00, 0xff, 0x51, 0x92, 0x00, 0xff, 0x51, 0x92, 0x00, 0xff,
		0x51, 0x92, 0x00, 0xff, 0x51, 0x92, 0x00, 0xff, 0x51, 0x92, 0x00, 0xff,
		0xa3, 0x01, 0x64, 0x50, 0x52, 0x6f, 0x54, 0x02, 0x58, 0x20, 0x05, 0x06,
		0x07, 0x08, 0x05, 0x06, 0x07, 0x08, 0x05, 0x06, 0x07, 0x08, 0x05, 0x06,
		0x07, 0x08, 0x05, 0x06, 0x07, 0x08, 0x05, 0x06, 0x07, 0x08, 0x05, 0x06,
		0x07, 0x08, 0x05, 0x06, 0x07, 0x08, 0x05, 0x58, 0x20, 0x51, 0x92, 0x00,
		0xff, 0x51, 0x92, 0x00, 0xff, 0x51, 0x92, 0x00, 0xff, 0x51, 0x92, 0x00,
		0xff, 0x51, 0x92, 0x00, 0xff, 0x51, 0x92, 0x00, 0xff, 0x51, 0x92, 0x00,
		0xff, 0x51, 0x92, 0x00, 0xff, 0x3a, 0x00, 0x01, 0x24, 0xff, 0x58, 0x20,
		0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03,
		0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03,
		0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 0x3a, 0x00, 0x01, 0x25,
		0x00, 0x58, 0x21, 0x01, 0xa0, 0xa1, 0xa2, 0xa3, 0xa0, 0xa1, 0xa2, 0xa3,
		0xa0, 0xa1, 0xa2, 0xa3, 0xa0, 0xa1, 0xa2, 0xa3, 0xa0, 0xa1, 0xa2, 0xa3,
		0xa0, 0xa1, 0xa2, 0xa3, 0xa0, 0xa1, 0xa2, 0xa3, 0xa0, 0xa1, 0xa2, 0xa3,
		0x3a, 0x00, 0x01, 0x25, 0x01, 0x78, 0x18, 0x68, 0x74, 0x74, 0x70, 0x73,
		0x3a, 0x2f, 0x2f, 0x70, 0x73, 0x61, 0x2d, 0x76, 0x65, 0x72, 0x69, 0x66,
		0x69, 0x65, 0x72, 0x2e, 0x6f, 0x72, 0x67,
	}

	actual, err := tv.ToCBOR()

	assert.Nil(t, err, "conversion to CBOR")
	assert.Equal(t, expected, actual, "CBOR encoded PSA token match")
}

func TestClaims_FromCBOR_ok(t *testing.T) {
	tv := []byte{
		0xaa, 0x3a, 0x00, 0x01, 0x24, 0xf7, 0x71, 0x50, 0x53, 0x41, 0x5f, 0x49,
		0x4f, 0x54, 0x5f, 0x50, 0x52, 0x4f, 0x46, 0x49, 0x4c, 0x45, 0x5f, 0x31,
		0x3a, 0x00, 0x01, 0x24, 0xf8, 0x01, 0x3a, 0x00, 0x01, 0x24, 0xf9, 0x19,
		0x30, 0x00, 0x3a, 0x00, 0x01, 0x24, 0xfa, 0x58, 0x20, 0x50, 0x51, 0x52,
		0x53, 0x54, 0x55, 0x56, 0x57, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56,
		0x57, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x50, 0x51, 0x52,
		0x53, 0x54, 0x55, 0x56, 0x57, 0x3a, 0x00, 0x01, 0x24, 0xfb, 0x58, 0x20,
		0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
		0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
		0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0x3a, 0x00, 0x01, 0x24,
		0xfc, 0x6d, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
		0x31, 0x32, 0x33, 0x3a, 0x00, 0x01, 0x24, 0xfd, 0x82, 0xa3, 0x01, 0x62,
		0x42, 0x4c, 0x02, 0x58, 0x20, 0x00, 0x01, 0x02, 0x04, 0x00, 0x01, 0x02,
		0x04, 0x00, 0x01, 0x02, 0x04, 0x00, 0x01, 0x02, 0x04, 0x00, 0x01, 0x02,
		0x04, 0x00, 0x01, 0x02, 0x04, 0x00, 0x01, 0x02, 0x04, 0x00, 0x01, 0x02,
		0x04, 0x05, 0x58, 0x20, 0x51, 0x92, 0x00, 0xff, 0x51, 0x92, 0x00, 0xff,
		0x51, 0x92, 0x00, 0xff, 0x51, 0x92, 0x00, 0xff, 0x51, 0x92, 0x00, 0xff,
		0x51, 0x92, 0x00, 0xff, 0x51, 0x92, 0x00, 0xff, 0x51, 0x92, 0x00, 0xff,
		0xa3, 0x01, 0x64, 0x50, 0x52, 0x6f, 0x54, 0x02, 0x58, 0x20, 0x05, 0x06,
		0x07, 0x08, 0x05, 0x06, 0x07, 0x08, 0x05, 0x06, 0x07, 0x08, 0x05, 0x06,
		0x07, 0x08, 0x05, 0x06, 0x07, 0x08, 0x05, 0x06, 0x07, 0x08, 0x05, 0x06,
		0x07, 0x08, 0x05, 0x06, 0x07, 0x08, 0x05, 0x58, 0x20, 0x51, 0x92, 0x00,
		0xff, 0x51, 0x92, 0x00, 0xff, 0x51, 0x92, 0x00, 0xff, 0x51, 0x92, 0x00,
		0xff, 0x51, 0x92, 0x00, 0xff, 0x51, 0x92, 0x00, 0xff, 0x51, 0x92, 0x00,
		0xff, 0x51, 0x92, 0x00, 0xff, 0x3a, 0x00, 0x01, 0x24, 0xff, 0x58, 0x20,
		0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03,
		0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03,
		0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 0x3a, 0x00, 0x01, 0x25,
		0x00, 0x58, 0x21, 0x01, 0xa0, 0xa1, 0xa2, 0xa3, 0xa0, 0xa1, 0xa2, 0xa3,
		0xa0, 0xa1, 0xa2, 0xa3, 0xa0, 0xa1, 0xa2, 0xa3, 0xa0, 0xa1, 0xa2, 0xa3,
		0xa0, 0xa1, 0xa2, 0xa3, 0xa0, 0xa1, 0xa2, 0xa3, 0xa0, 0xa1, 0xa2, 0xa3,
		0x3a, 0x00, 0x01, 0x25, 0x01, 0x78, 0x18, 0x68, 0x74, 0x74, 0x70, 0x73,
		0x3a, 0x2f, 0x2f, 0x70, 0x73, 0x61, 0x2d, 0x76, 0x65, 0x72, 0x69, 0x66,
		0x69, 0x65, 0x72, 0x2e, 0x6f, 0x72, 0x67,
	}

	expected := makeClaims()

	actual := Claims{}
	err := actual.FromCBOR(tv)

	assert.Nil(t, err, "conversion from CBOR")
	assert.Equal(t, expected, actual, "decoded PSA token match")
}

func TestClaims_ToJSON_ok(t *testing.T) {
	tv := makeClaims()

	expected := `{
  "profile": "PSA_IOT_PROFILE_1",
  "partition-id": 1,
  "_partition-id-desc": "spe",
  "security-life-cycle": 12288,
  "_security-lifecycle-desc": "secured",
  "implementation-id": "UFFSU1RVVldQUVJTVFVWV1BRUlNUVVZXUFFSU1RVVlc=",
  "boot-seed": "3q2+796tvu/erb7v3q2+796tvu/erb7v3q2+796tvu8=",
  "hardware-version": "1234567890123",
  "software-components": [
    {
      "measurement-type": "BL",
      "measurement-value": "AAECBAABAgQAAQIEAAECBAABAgQAAQIEAAECBAABAgQ=",
      "signer-id": "UZIA/1GSAP9RkgD/UZIA/1GSAP9RkgD/UZIA/1GSAP8="
    },
    {
      "measurement-type": "PRoT",
      "measurement-value": "BQYHCAUGBwgFBgcIBQYHCAUGBwgFBgcIBQYHCAUGBwg=",
      "signer-id": "UZIA/1GSAP9RkgD/UZIA/1GSAP9RkgD/UZIA/1GSAP8="
    }
  ],
  "nonce": "AAECAwABAgMAAQIDAAECAwABAgMAAQIDAAECAwABAgM=",
  "instance-id": "AaChoqOgoaKjoKGio6ChoqOgoaKjoKGio6ChoqOgoaKj",
  "verification-service-indicator": "https://psa-verifier.org"
}`

	actual, err := tv.ToJSON()

	assert.Nil(t, err, "conversion to JSON failed")
	assert.JSONEq(t, expected, actual, "JSON encoded PSA token does not match")
}

func TestClaims_sign_and_verify(t *testing.T) {
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

	var PSATokenIn Evidence

	PSATokenIn.Claims = makeClaims()

	cwt, err := PSATokenIn.Sign(tokenSigner)
	assert.Nil(t, err, "signing failed")

	var PSATokenOut Evidence

	err = PSATokenOut.FromCOSE(cwt)
	assert.Nil(t, err, "Sign1Message decoding failed")

	err = PSATokenOut.Verify(tokenSigner.Verifier().PublicKey)
	assert.Nil(t, err, "verification failed")
}

func makeClaims() Claims {
	profile := PSA_PROFILE_1
	partitionID := int32(1)
	securityLifeCycle := uint16(SECURITY_LIFECYCLE_SECURED_MIN)
	hwVersion := "1234567890123"

	return Claims{
		Profile:               &profile,
		PartitionID:           &partitionID,
		PartitionIDDesc:       "spe",
		SecurityLifeCycle:     &securityLifeCycle,
		SecurityLifeCycleDesc: "secured",
		ImplID: &[]byte{
			0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
			0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
			0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
			0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
		},
		BootSeed: &[]byte{
			0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
			0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
			0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
			0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
		},
		HwVersion: &hwVersion,
		SwComponents: []SwComponent{
			{
				MeasurementType: "BL",
				MeasurementValue: &[]byte{
					0x00, 0x01, 0x02, 0x04, 0x00, 0x01, 0x02, 0x04,
					0x00, 0x01, 0x02, 0x04, 0x00, 0x01, 0x02, 0x04,
					0x00, 0x01, 0x02, 0x04, 0x00, 0x01, 0x02, 0x04,
					0x00, 0x01, 0x02, 0x04, 0x00, 0x01, 0x02, 0x04,
				},
				SignerID: &[]byte{
					0x51, 0x92, 0x00, 0xff, 0x51, 0x92, 0x00, 0xff,
					0x51, 0x92, 0x00, 0xff, 0x51, 0x92, 0x00, 0xff,
					0x51, 0x92, 0x00, 0xff, 0x51, 0x92, 0x00, 0xff,
					0x51, 0x92, 0x00, 0xff, 0x51, 0x92, 0x00, 0xff,
				},
			},
			{
				MeasurementType: "PRoT",
				MeasurementValue: &[]byte{
					0x05, 0x06, 0x07, 0x08, 0x05, 0x06, 0x07, 0x08,
					0x05, 0x06, 0x07, 0x08, 0x05, 0x06, 0x07, 0x08,
					0x05, 0x06, 0x07, 0x08, 0x05, 0x06, 0x07, 0x08,
					0x05, 0x06, 0x07, 0x08, 0x05, 0x06, 0x07, 0x08,
				},
				SignerID: &[]byte{
					0x51, 0x92, 0x00, 0xff, 0x51, 0x92, 0x00, 0xff,
					0x51, 0x92, 0x00, 0xff, 0x51, 0x92, 0x00, 0xff,
					0x51, 0x92, 0x00, 0xff, 0x51, 0x92, 0x00, 0xff,
					0x51, 0x92, 0x00, 0xff, 0x51, 0x92, 0x00, 0xff,
				},
			},
		},
		Nonce: &[]byte{
			0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03,
			0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03,
			0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03,
			0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03,
		},
		InstID: &[]byte{
			0x01,
			0xa0, 0xa1, 0xa2, 0xa3, 0xa0, 0xa1, 0xa2, 0xa3,
			0xa0, 0xa1, 0xa2, 0xa3, 0xa0, 0xa1, 0xa2, 0xa3,
			0xa0, 0xa1, 0xa2, 0xa3, 0xa0, 0xa1, 0xa2, 0xa3,
			0xa0, 0xa1, 0xa2, 0xa3, 0xa0, 0xa1, 0xa2, 0xa3,
		},
		VSI: "https://psa-verifier.org",
	}
}
