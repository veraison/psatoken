// Copyright 2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package psatoken

import (
	"errors"
	"fmt"
	"log"

	"github.com/veraison/eat"
	"github.com/veraison/psatoken/encoding"
)

// This is an example of implementing a new profile by embedding and extending
// an existing one. For an example of a complete profile implementation without
// relying on embedding, refer to the [two](claims_p1.go)
// [profiles](claims_p2.go) implemented as part of this library.
// The example profile is based on Profile2, but adds the following
// modifications:
//  - add new claim, timestamp
//  - further constrain nonce to be exactly 48 bytes

// --- extension definition ---

type ExampleClaims struct {
	// embed P2Claims to inherit existing implementation
	P2Claims

	// add new claim
	Timestamp *int64 `cbor:"-75100,keyasint,omitempty" json:"timestamp,omitempty"`
}

func (o *ExampleClaims) SetTimestamp(v int64) error {
	if v < 0 {
		return errors.New("negative timestamp")
	}

	o.Timestamp = &v
	return nil
}

func (o *ExampleClaims) GetTimestamp() (int64, error) {
	if o.Timestamp == nil {
		return 0, ErrMissingOptional
	}

	if *o.Timestamp < 0 {
		return 0, errors.New("negative timestamp")
	}

	return *o.Timestamp, nil
}

func (o *ExampleClaims) Validate() error {
	// "baseline" validation of P2 claims
	if err := ValidateClaims(o); err != nil {
		return err
	}

	// validate the new claim. Note that filter error will filter out
	// ErrMissingOptional (as it is valid to not specify an optional
	// claim).
	if err := FilterError(o.GetTimestamp()); err != nil {
		return err
	}

	// validate additional constraint on the nonce
	nonce, err := o.GetNonce()
	if err != nil {
		// note: should not actually get here, as was validated by
		// ValidateClaims above.
		return err
	}

	if len(nonce) != 48 {
		return errors.New("nonce must be exactly 48 bytes")
	}

	return nil
}

// To ensure embedding is handled correctly during marshaling, we need to use
// custom encoding functions, which means implementing the eight marshaling
// methods defined by IClaims.

func (o ExampleClaims) MarshalCBOR() ([]byte, error) { //nolint:gocritic
	return encoding.SerializeStructToCBOR(em, &o)
}

func (o *ExampleClaims) UnmarshalCBOR(data []byte) error {
	return encoding.PopulateStructFromCBOR(dm, data, o)
}

func (o ExampleClaims) MarshalJSON() ([]byte, error) { //nolint:gocritic
	return encoding.SerializeStructToJSON(&o)

}
func (o *ExampleClaims) UnmarshalJSON(data []byte) error {
	return encoding.PopulateStructFromJSON(data, o)
}

// Name of the profile associated with ExampleClaims
const ExampleProfileName = "http://example.com/psa"

// factory function for ExampleClaims
func NewExampleClaims() IClaims {
	p := eat.Profile{}
	if err := p.Set(ExampleProfileName); err != nil {
		// should never get here as using known good constant as input
		panic(err)
	}

	return &ExampleClaims{
		P2Claims: P2Claims{
			Profile: &p,

			// We need to provide an implementation of
			// ISwComponent; as we're not extending software
			// components, we're using the default implmentation
			SwComponents: &SwComponents[*SwComponent]{},

			// setting CanonicalProfile to our profile name, as we will be
			// relying on the P2Claims's implementation to validate
			// Profile claim,
			CanonicalProfile: ExampleProfileName,
		},
	}
}

// Implementation of IProfile. This is used to register the new IClaims
// implementation and associated it with the profile name.
type ExampleProfile struct{}

func (o ExampleProfile) GetName() string {
	return ExampleProfileName
}

func (o ExampleProfile) GetClaims() IClaims {
	return NewExampleClaims()
}

// Registering the profile inside init() to ensure that it it is available to
// the general NewClaims() and DecodeClaims() functions, and the IClaims
// implementation associated with the profile will automatically be used when
// the profile in the data matches the registered name.
func init() {
	if err := RegisterProfile(ExampleProfile{}); err != nil {
		panic(err)
	}
}

// --- end of extension definition ---

func Example_unmarashal() {
	input := []byte(`
	{
	  "eat-profile": "http://example.com/psa",
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

	claims, err := DecodeAndValidateClaimsFromJSON(input)
	if err != nil {
		log.Fatalf("could not decode claims: %v", err)
	}

	profileName, err := claims.GetProfile()
	if err != nil {
		log.Fatalf("could not get profile: %v", err)
	}
	fmt.Printf("Profile: %s\n", profileName)

	exampleClaims, ok := claims.(*ExampleClaims)
	if !ok {
		log.Fatalf("not a *ExampleClaims: %T", claims)
	}

	ts, err := exampleClaims.GetTimestamp()
	if err != nil {
		log.Fatalf("could not get timestamp: %v", err)
	}
	fmt.Printf("Timestamp: %d\n", ts)

	// output:
	// Profile: http://example.com/psa
	// Timestamp: 1721138454
}

func Example_marshal() {
	// note: for the sake of example, these bytes will be used in multiple
	// places when constructing the claims. In reality, you would, of
	// course, use appropriate data for each claim.
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

	// note: alternatively, can call NewExampleClaims() directly
	claims, err := NewClaims(ExampleProfileName)
	if err != nil {
		log.Fatalf("could not create new claims: %v", err)
	}

	if err = claims.SetClientID(1); err != nil {
		log.Fatalf("could not set client ID: %v", err)
	}

	if err = claims.SetSecurityLifeCycle(12288); err != nil {
		log.Fatalf("could not set security life cycle: %v", err)
	}

	if err = claims.SetImplID(exampleBytes); err != nil {
		log.Fatalf("could not set implementation ID: %v", err)
	}

	if err = claims.SetInstID(instIDBytes); err != nil {
		log.Fatalf("could not set instance ID: %v", err)
	}

	if err = claims.SetNonce(nonceBytes); err != nil {
		log.Fatalf("could not set nonce: %v", err)
	}

	swComponents := []ISwComponent{
		&SwComponent{
			MeasurementValue: &exampleBytes,
			SignerID:         &exampleBytes,
		},
	}
	if err = claims.SetSoftwareComponents(swComponents); err != nil {
		log.Fatalf("could not set implementation ID: %v", err)
	}

	exampleClaims, ok := claims.(*ExampleClaims)
	if !ok {
		log.Fatalf("not a *ExampleClaims: %T", claims)
	}

	if err = exampleClaims.SetTimestamp(1721138454); err != nil {
		log.Fatalf("could not set timestamp: %v", err)
	}

	out, err := exampleClaims.MarshalJSON()
	if err != nil {
		log.Fatalf("could not marshal claims: %v", err)
	}

	fmt.Printf("marshaled claims: %s", string(out))

	// output:
	// marshaled claims: {"timestamp":1721138454,"eat-profile":"http://example.com/psa","psa-client-id":1,"psa-security-lifecycle":12288,"psa-implementation-id":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=","psa-software-components":[{"measurement-value":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=","signer-id":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="}],"psa-nonce":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyABAgMEBQYHCAkKCwwNDg8Q","psa-instance-id":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAh"}
}
