// Copyright 2021 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package psatoken

import (
	_ "crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/eat"
)

var (
	testInstID = &eat.UEID{
		0x01,
		0xa0, 0xa1, 0xa2, 0xa3, 0xa0, 0xa1, 0xa2, 0xa3,
		0xa0, 0xa1, 0xa2, 0xa3, 0xa0, 0xa1, 0xa2, 0xa3,
		0xa0, 0xa1, 0xa2, 0xa3, 0xa0, 0xa1, 0xa2, 0xa3,
		0xa0, 0xa1, 0xa2, 0xa3, 0xa0, 0xa1, 0xa2, 0xa3,
	}

	testNonce = []byte{
		0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03,
		0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03,
		0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03,
		0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03,
	}

	testUnknownProfile = "http://unknown/profile/1.2.3"
)

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

		err = p.validate(PSA_PROFILE_2)
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
			eStr:  "got profile 'http://UNKNOWN' want 'http://arm.com/psa/2.0.0'",
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
			eStr:  "invalid nonce: length 4 (psa-hash-type MUST be 32, 48 or 64 bytes)",
		},
		// 13
		{
			fPath: "testvectors/test-nonce-invalid-long.json",
			eStr:  "invalid nonce: length 65 (psa-hash-type MUST be 32, 48 or 64 bytes)",
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
		// 24
		{
			fPath: "testvectors/test-profile-invalid-missing.json",
			eStr:  "profile claim missing",
		},
	}

	for i, tc := range tCases {
		p, err := loadJSONTestVectorFromFile(tc.fPath)
		require.Nil(t, err, "unable to load %s: %v", tc.fPath, err)

		err = p.validate(PSA_PROFILE_2)
		assert.EqualError(t, err, tc.eStr, "failed TCase at index %d (%s)", i, tc.fPath)
	}
}

func TestClaims_ToCBOR_ok(t *testing.T) {
	tv := makeClaims(t)

	// {265: "http://arm.com/psa/2.0.0", -75001: 1, -75002: 12288, -75003: h'5051525354555657505152535455565750515253545556575051525354555657', -75004: h'DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF', -75005: "1234567890123", -75006: [{1: "BL", 2: h'0001020400010204000102040001020400010204000102040001020400010204', 5: h'519200FF519200FF519200FF519200FF519200FF519200FF519200FF519200FF'}, {1: "PRoT", 2: h'0506070805060708050607080506070805060708050607080506070805060708', 5: h'519200FF519200FF519200FF519200FF519200FF519200FF519200FF519200FF'}], 10: h'0001020300010203000102030001020300010203000102030001020300010203', 256: h'01A0A1A2A3A0A1A2A3A0A1A2A3A0A1A2A3A0A1A2A3A0A1A2A3A0A1A2A3A0A1A2A3', -75010: "https://psa-verifier.org"}
	expected := []byte{
		0xaa, 0x19, 0x01, 0x09, 0x78, 0x18, 0x68, 0x74, 0x74, 0x70,
		0x3a, 0x2f, 0x2f, 0x61, 0x72, 0x6d, 0x2e, 0x63, 0x6f, 0x6d,
		0x2f, 0x70, 0x73, 0x61, 0x2f, 0x32, 0x2e, 0x30, 0x2e, 0x30,
		0x3a, 0x00, 0x01, 0x24, 0xf8, 0x01, 0x3a, 0x00, 0x01, 0x24,
		0xf9, 0x19, 0x30, 0x00, 0x3a, 0x00, 0x01, 0x24, 0xfa, 0x58,
		0x20, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x50,
		0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x50, 0x51, 0x52,
		0x53, 0x54, 0x55, 0x56, 0x57, 0x50, 0x51, 0x52, 0x53, 0x54,
		0x55, 0x56, 0x57, 0x3a, 0x00, 0x01, 0x24, 0xfb, 0x58, 0x20,
		0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad,
		0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
		0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad,
		0xbe, 0xef, 0x3a, 0x00, 0x01, 0x24, 0xfc, 0x6d, 0x31, 0x32,
		0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32,
		0x33, 0x3a, 0x00, 0x01, 0x24, 0xfd, 0x82, 0xa3, 0x01, 0x62,
		0x42, 0x4c, 0x02, 0x58, 0x20, 0x00, 0x01, 0x02, 0x04, 0x00,
		0x01, 0x02, 0x04, 0x00, 0x01, 0x02, 0x04, 0x00, 0x01, 0x02,
		0x04, 0x00, 0x01, 0x02, 0x04, 0x00, 0x01, 0x02, 0x04, 0x00,
		0x01, 0x02, 0x04, 0x00, 0x01, 0x02, 0x04, 0x05, 0x58, 0x20,
		0x51, 0x92, 0x00, 0xff, 0x51, 0x92, 0x00, 0xff, 0x51, 0x92,
		0x00, 0xff, 0x51, 0x92, 0x00, 0xff, 0x51, 0x92, 0x00, 0xff,
		0x51, 0x92, 0x00, 0xff, 0x51, 0x92, 0x00, 0xff, 0x51, 0x92,
		0x00, 0xff, 0xa3, 0x01, 0x64, 0x50, 0x52, 0x6f, 0x54, 0x02,
		0x58, 0x20, 0x05, 0x06, 0x07, 0x08, 0x05, 0x06, 0x07, 0x08,
		0x05, 0x06, 0x07, 0x08, 0x05, 0x06, 0x07, 0x08, 0x05, 0x06,
		0x07, 0x08, 0x05, 0x06, 0x07, 0x08, 0x05, 0x06, 0x07, 0x08,
		0x05, 0x06, 0x07, 0x08, 0x05, 0x58, 0x20, 0x51, 0x92, 0x00,
		0xff, 0x51, 0x92, 0x00, 0xff, 0x51, 0x92, 0x00, 0xff, 0x51,
		0x92, 0x00, 0xff, 0x51, 0x92, 0x00, 0xff, 0x51, 0x92, 0x00,
		0xff, 0x51, 0x92, 0x00, 0xff, 0x51, 0x92, 0x00, 0xff, 0x0a,
		0x58, 0x20, 0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03,
		0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 0x00, 0x01,
		0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03,
		0x00, 0x01, 0x02, 0x03, 0x19, 0x01, 0x00, 0x58, 0x21, 0x01,
		0xa0, 0xa1, 0xa2, 0xa3, 0xa0, 0xa1, 0xa2, 0xa3, 0xa0, 0xa1,
		0xa2, 0xa3, 0xa0, 0xa1, 0xa2, 0xa3, 0xa0, 0xa1, 0xa2, 0xa3,
		0xa0, 0xa1, 0xa2, 0xa3, 0xa0, 0xa1, 0xa2, 0xa3, 0xa0, 0xa1,
		0xa2, 0xa3, 0x3a, 0x00, 0x01, 0x25, 0x01, 0x78, 0x18, 0x68,
		0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x70, 0x73, 0x61,
		0x2d, 0x76, 0x65, 0x72, 0x69, 0x66, 0x69, 0x65, 0x72, 0x2e,
		0x6f, 0x72, 0x67,
	}

	actual, err := tv.ToCBOR()

	log.Printf("%x\n", actual)

	assert.Nil(t, err, "conversion to CBOR")
	assert.Equal(t, expected, actual, "CBOR encoded PSA token match")
}

func TestClaims_FromCBOR_ok(t *testing.T) {
	// {265: "http://arm.com/psa/2.0.0", -75001: 1, -75002: 12288, -75003: h'5051525354555657505152535455565750515253545556575051525354555657', -75004: h'DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF', -75005: "1234567890123", -75006: [{1: "BL", 2: h'0001020400010204000102040001020400010204000102040001020400010204', 5: h'519200FF519200FF519200FF519200FF519200FF519200FF519200FF519200FF'}, {1: "PRoT", 2: h'0506070805060708050607080506070805060708050607080506070805060708', 5: h'519200FF519200FF519200FF519200FF519200FF519200FF519200FF519200FF'}], 10: h'0001020300010203000102030001020300010203000102030001020300010203', 256: h'01A0A1A2A3A0A1A2A3A0A1A2A3A0A1A2A3A0A1A2A3A0A1A2A3A0A1A2A3A0A1A2A3', -75010: "https://psa-verifier.org", -75009: null, -75000: null, -75008: null}
	tv := []byte{
		0xad, 0x19, 0x01, 0x09, 0x78, 0x18, 0x68, 0x74, 0x74, 0x70,
		0x3a, 0x2f, 0x2f, 0x61, 0x72, 0x6d, 0x2e, 0x63, 0x6f, 0x6d,
		0x2f, 0x70, 0x73, 0x61, 0x2f, 0x32, 0x2e, 0x30, 0x2e, 0x30,
		0x3a, 0x00, 0x01, 0x24, 0xf8, 0x01, 0x3a, 0x00, 0x01, 0x24,
		0xf9, 0x19, 0x30, 0x00, 0x3a, 0x00, 0x01, 0x24, 0xfa, 0x58,
		0x20, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x50,
		0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x50, 0x51, 0x52,
		0x53, 0x54, 0x55, 0x56, 0x57, 0x50, 0x51, 0x52, 0x53, 0x54,
		0x55, 0x56, 0x57, 0x3a, 0x00, 0x01, 0x24, 0xfb, 0x58, 0x20,
		0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad,
		0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
		0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad,
		0xbe, 0xef, 0x3a, 0x00, 0x01, 0x24, 0xfc, 0x6d, 0x31, 0x32,
		0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32,
		0x33, 0x3a, 0x00, 0x01, 0x24, 0xfd, 0x82, 0xa3, 0x01, 0x62,
		0x42, 0x4c, 0x02, 0x58, 0x20, 0x00, 0x01, 0x02, 0x04, 0x00,
		0x01, 0x02, 0x04, 0x00, 0x01, 0x02, 0x04, 0x00, 0x01, 0x02,
		0x04, 0x00, 0x01, 0x02, 0x04, 0x00, 0x01, 0x02, 0x04, 0x00,
		0x01, 0x02, 0x04, 0x00, 0x01, 0x02, 0x04, 0x05, 0x58, 0x20,
		0x51, 0x92, 0x00, 0xff, 0x51, 0x92, 0x00, 0xff, 0x51, 0x92,
		0x00, 0xff, 0x51, 0x92, 0x00, 0xff, 0x51, 0x92, 0x00, 0xff,
		0x51, 0x92, 0x00, 0xff, 0x51, 0x92, 0x00, 0xff, 0x51, 0x92,
		0x00, 0xff, 0xa3, 0x01, 0x64, 0x50, 0x52, 0x6f, 0x54, 0x02,
		0x58, 0x20, 0x05, 0x06, 0x07, 0x08, 0x05, 0x06, 0x07, 0x08,
		0x05, 0x06, 0x07, 0x08, 0x05, 0x06, 0x07, 0x08, 0x05, 0x06,
		0x07, 0x08, 0x05, 0x06, 0x07, 0x08, 0x05, 0x06, 0x07, 0x08,
		0x05, 0x06, 0x07, 0x08, 0x05, 0x58, 0x20, 0x51, 0x92, 0x00,
		0xff, 0x51, 0x92, 0x00, 0xff, 0x51, 0x92, 0x00, 0xff, 0x51,
		0x92, 0x00, 0xff, 0x51, 0x92, 0x00, 0xff, 0x51, 0x92, 0x00,
		0xff, 0x51, 0x92, 0x00, 0xff, 0x51, 0x92, 0x00, 0xff, 0x0a,
		0x58, 0x20, 0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03,
		0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 0x00, 0x01,
		0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03,
		0x00, 0x01, 0x02, 0x03, 0x19, 0x01, 0x00, 0x58, 0x21, 0x01,
		0xa0, 0xa1, 0xa2, 0xa3, 0xa0, 0xa1, 0xa2, 0xa3, 0xa0, 0xa1,
		0xa2, 0xa3, 0xa0, 0xa1, 0xa2, 0xa3, 0xa0, 0xa1, 0xa2, 0xa3,
		0xa0, 0xa1, 0xa2, 0xa3, 0xa0, 0xa1, 0xa2, 0xa3, 0xa0, 0xa1,
		0xa2, 0xa3, 0x3a, 0x00, 0x01, 0x25, 0x01, 0x78, 0x18, 0x68,
		0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x70, 0x73, 0x61,
		0x2d, 0x76, 0x65, 0x72, 0x69, 0x66, 0x69, 0x65, 0x72, 0x2e,
		0x6f, 0x72, 0x67, 0x3a, 0x00, 0x01, 0x25, 0x00, 0xf6, 0x3a,
		0x00, 0x01, 0x24, 0xf7, 0xf6, 0x3a, 0x00, 0x01, 0x24, 0xff,
		0xf6,
	}

	expected := makeClaims(t)

	actual := Claims{}
	err := actual.FromCBOR(tv)

	assert.Nil(t, err, "conversion from CBOR")
	assert.Equal(t, expected, actual, "decoded PSA token match")
}

func TestClaims_ToJSON_ok(t *testing.T) {
	tv := makeClaims(t)

	expected := `{
  "profile": "http://arm.com/psa/2.0.0",
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

func TestClaims_GetProfile_no_profile(t *testing.T) {
	tv := Claims{}

	_, err := tv.GetProfile()
	assert.EqualError(t, err, "no profile set")
}

func TestClaims_GetProfile_confusing_profile_settings(t *testing.T) {
	newProfile, err := eat.NewProfile(PSA_PROFILE_2)
	require.Nil(t, err)

	oldProfile := PSA_PROFILE_1

	tv := Claims{
		Profile:       newProfile,
		LegacyProfile: &oldProfile,
	}

	_, err = tv.GetProfile()
	assert.EqualError(t, err, "both legacy and new profile claims are set")
}

func TestClaims_GetProfile_legacy_ok(t *testing.T) {
	oldProfile := PSA_PROFILE_1

	tv := Claims{
		LegacyProfile: &oldProfile,
	}

	expected := PSA_PROFILE_1

	actual, err := tv.GetProfile()

	assert.Nil(t, err)
	assert.Equal(t, expected, actual)
}

func TestClaims_GetNonce_legacy_ok(t *testing.T) {
	expected := testNonce

	oldProfile := PSA_PROFILE_1

	tv := Claims{
		LegacyProfile: &oldProfile,
		LegacyNonce:   &expected,
	}

	actual, err := tv.GetNonce()

	assert.Nil(t, err)
	assert.Equal(t, expected, actual)
}

func TestClaims_GetNonce_ok(t *testing.T) {
	profile, err := eat.NewProfile(PSA_PROFILE_2)
	require.NoError(t, err)

	nonce := eat.Nonce{}
	require.NoError(t, nonce.Add(testNonce))

	tv := Claims{
		Profile: profile,
		Nonce:   &nonce,
	}

	actual, err := tv.GetNonce()

	assert.Nil(t, err)
	assert.Equal(t, testNonce, actual)
}

func TestClaims_GetNonce_profile2_mismatch(t *testing.T) {
	profile, err := eat.NewProfile(PSA_PROFILE_2)
	require.NoError(t, err)

	tv := Claims{
		Profile:     profile,
		LegacyNonce: &testNonce,
	}

	_, err = tv.GetNonce()

	assert.EqualError(t, err, "missing mandatory nonce")
}

func TestClaims_GetNonce_profile1_mismatch(t *testing.T) {
	profile := PSA_PROFILE_1

	nonce := eat.Nonce{}
	require.NoError(t, nonce.Add(testNonce))

	tv := Claims{
		LegacyProfile: &profile,
		Nonce:         &nonce,
	}

	_, err := tv.GetNonce()

	assert.EqualError(t, err, "missing mandatory nonce")
}

func TestClaims_GetNonce_unknown_profile(t *testing.T) {
	profile, err := eat.NewProfile(testUnknownProfile)
	require.NoError(t, err)

	tv := Claims{
		Profile:     profile,
		LegacyNonce: &testNonce,
	}

	expectedErr := fmt.Sprintf("unknown profile: %s", testUnknownProfile)

	_, err = tv.GetNonce()

	assert.EqualError(t, err, expectedErr)
}

func TestClaims_GetNonce_no_profile(t *testing.T) {
	nonce := eat.Nonce{}
	require.NoError(t, nonce.Add(testNonce))

	legacyNonce := testNonce

	tv := Claims{
		Nonce:       &nonce,
		LegacyNonce: &legacyNonce,
	}

	_, err := tv.GetNonce()

	assert.EqualError(t, err, "no profile set")
}

func TestClaims_GetProfile_profile2_ok(t *testing.T) {
	newProfile, err := eat.NewProfile(PSA_PROFILE_2)
	require.Nil(t, err)

	tv := Claims{
		Profile: newProfile,
	}

	expected := PSA_PROFILE_2

	actual, err := tv.GetProfile()

	assert.Nil(t, err)
	assert.Equal(t, expected, actual)
}

func TestClaims_SetNonce_unknown_profile(t *testing.T) {
	profile, err := eat.NewProfile(testUnknownProfile)
	require.NoError(t, err)

	var nonce eat.Nonce
	err = nonce.Add(testNonce)
	require.NoError(t, err)

	c := Claims{
		Profile: profile,
		Nonce:   &nonce,
	}

	expectedErr := fmt.Sprintf("unknown profile: %s", testUnknownProfile)

	err = c.SetNonce(testNonce)
	assert.EqualError(t, err, expectedErr)
}

func TestClaims_SetNonce_already_set(t *testing.T) {
	profile, err := eat.NewProfile(PSA_PROFILE_2)
	require.NoError(t, err)

	var nonce eat.Nonce
	err = nonce.Add(testNonce)
	require.NoError(t, err)

	c := Claims{
		Profile: profile,
		Nonce:   &nonce,
	}

	expectedErr := "nonce already set"

	err = c.SetNonce(testNonce)
	assert.EqualError(t, err, expectedErr)
}

func TestClaims_SetNonce_profile2_ok_roundtrip(t *testing.T) {
	profile, err := eat.NewProfile(PSA_PROFILE_2)
	require.NoError(t, err)

	c := Claims{
		Profile: profile,
	}

	err = c.SetNonce(testNonce)
	assert.NoError(t, err)

	actual, err := c.GetNonce()
	assert.NoError(t, err)
	assert.Equal(t, testNonce, actual)
}

func TestClaims_SetNonce_profile1_ok_roundtrip(t *testing.T) {
	profile := PSA_PROFILE_1

	c := Claims{
		LegacyProfile: &profile,
	}

	err := c.SetNonce(testNonce)
	assert.NoError(t, err)

	actual, err := c.GetNonce()
	assert.NoError(t, err)
	assert.Equal(t, testNonce, actual)
}

func TestClaims_SetNonce_wrong_size(t *testing.T) {
	c := Claims{}

	nonceWrongSize := []byte("ninebytes")

	expectedErr := "length 9 (psa-hash-type MUST be 32, 48 or 64 bytes)"

	err := c.SetNonce(nonceWrongSize)

	assert.EqualError(t, err, expectedErr)
}

func TestClaims_SetNonce_without_profile(t *testing.T) {
	c := Claims{}

	expectedErr := "no profile set"

	err := c.SetNonce(testNonce)

	assert.EqualError(t, err, expectedErr)
}

func makeClaims(t *testing.T) Claims {
	profile, err := eat.NewProfile(PSA_PROFILE_2)
	require.Nil(t, err)

	nonce := eat.Nonce{}
	err = nonce.Add(testNonce)
	require.Nil(t, err)

	partitionID := int32(1)
	securityLifeCycle := uint16(SECURITY_LIFECYCLE_SECURED_MIN)
	hwVersion := "1234567890123"

	return Claims{
		Profile:               profile,
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
		Nonce:  &nonce,
		InstID: testInstID,
		VSI:    "https://psa-verifier.org",
	}
}
