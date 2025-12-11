// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package psatoken

import (
	"fmt"
	"log"
)

func ExampleRFC9783Claims_unmarshalCBOR() {
	input := mustHexDecode(nil, testEncodedRFC9783ClaimsAll)

	claims := NewRFC9783Claims()

	if err := claims.UnmarshalCBOR(input); err != nil {
		log.Fatalf("could not decode claims: %v", err)
	}

	if err := claims.Validate(); err != nil {
		log.Fatalf("could not validate claims: %v", err)
	}

	profileName, err := claims.GetProfile()
	if err != nil {
		log.Fatalf("could not get profile: %v", err)
	}
	fmt.Printf("Profile: %s\n", profileName)

	// output:
	// Profile: tag:psacertified.org,2023:psa#tfm
}

func ExampleRFC9783Claims_marshalCBOR() {
	rfc9783Claims := claims9783ExampleSetup()

	out, err := rfc9783Claims.MarshalCBOR()
	if err != nil {
		log.Fatalf("could not marshal claims: %v", err)
	}

	fmt.Printf("marshaled claims: %x", out)

	// output:
	// marshaled claims: a819010c48626f6f747365656419010978217461673a7073616365727469666965642e6f72672c323032333a7073612374666d19095a0119095b19300019095c58200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2019095f81a20258200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200558200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200a58300102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200102030405060708090a0b0c0d0e0f1019010058210102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021
}

func ExampleRFC9783Claims_unmarshalJSON() {
	input := []byte(`
	{
	  "eat-profile": "tag:psacertified.org,2023:psa#tfm",
	  "psa-client-id": 1,
	  "psa-security-lifecycle": 12288,
	  "psa-implementation-id": "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
	  "psa-boot-seed": "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
	  "psa-hwver": "1234567890123",
	  "psa-software-components": [
	    {
	      "measurement-type": "BL",
	      "measurement-value": "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
	      "signer-id": "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="
	    }
	  ],
	  "psa-nonce": "AQIDBAUGBwgJCgsMDQ4PEAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g",
	  "psa-instance-id": "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAh",
	  "psa-verification-service-indicator": "https://psa-verifier.org",
	  "psa-certification-reference": "1234567890123-12345",
	  "timestamp": 1721138454
	}
	`)

	claims := NewRFC9783Claims()

	if err := claims.UnmarshalJSON(input); err != nil {
		log.Fatalf("could not decode claims: %v", err)
	}

	if err := claims.Validate(); err != nil {
		log.Fatalf("could not validate claims: %v", err)
	}

	profileName, err := claims.GetProfile()
	if err != nil {
		log.Fatalf("could not get profile: %v", err)
	}
	fmt.Printf("Profile: %s\n", profileName)

	// output:
	// Profile: tag:psacertified.org,2023:psa#tfm
}

func ExampleRFC9783Claims_marshalJSON() {
	rfc9783Claims := claims9783ExampleSetup()

	out, err := rfc9783Claims.MarshalJSON()
	if err != nil {
		log.Fatalf("could not marshal claims: %v", err)
	}

	fmt.Printf("marshaled claims: %s", string(out))

	// output:
	// marshaled claims: {"psa-boot-seed":"Ym9vdHNlZWQ=","eat-profile":"tag:psacertified.org,2023:psa#tfm","psa-client-id":1,"psa-security-lifecycle":12288,"psa-implementation-id":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=","psa-software-components":[{"measurement-value":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=","signer-id":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="}],"psa-nonce":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyABAgMEBQYHCAkKCwwNDg8Q","psa-instance-id":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAh"}
}

func claims9783ExampleSetup() *RFC9783Claims {
	exampleBytes := []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
		0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
		0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
		0x1f, 0x20,
	}

	// instance id must be 33 bytes
	instIDBytes := append(exampleBytes, 0x21) // nolint:gocritic

	// as per our profile, nonce must be 48 bytes
	nonceBytes := append(exampleBytes, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // nolint:gocritic
		0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10)

	claims := NewRFC9783Claims()

	if err := claims.SetClientID(1); err != nil {
		log.Fatalf("could not set client ID: %v", err)
	}

	if err := claims.SetSecurityLifeCycle(12288); err != nil {
		log.Fatalf("could not set security life cycle: %v", err)
	}

	if err := claims.SetImplID(exampleBytes); err != nil {
		log.Fatalf("could not set implementation ID: %v", err)
	}

	if err := claims.SetInstID(instIDBytes); err != nil {
		log.Fatalf("could not set instance ID: %v", err)
	}

	if err := claims.SetNonce(nonceBytes); err != nil {
		log.Fatalf("could not set nonce: %v", err)
	}

	if err := claims.SetBootSeed([]byte("bootseed")); err != nil {
		log.Fatalf("could not set boot seed: %v", err)
	}

	swComponents := []ISwComponent{
		&SwComponent{
			MeasurementValue: &exampleBytes,
			SignerID:         &exampleBytes,
		},
	}
	if err := claims.SetSoftwareComponents(swComponents); err != nil {
		log.Fatalf("could not set software components: %v", err)
	}

	return claims
}
