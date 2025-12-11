// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package psatoken

import (
	"fmt"

	"github.com/veraison/eat"
	"github.com/veraison/psatoken/encoding"
)

type RFC9783Claims struct {
	// embed P2Claims to inherit existing implementation
	P2Claims

	// Override BootSeed to use different CBOR key as per RFC 9783 (268 vs 2397)
	BootSeed *[]byte `cbor:"268,keyasint,omitempty" json:"psa-boot-seed,omitempty"`
}

func (o *RFC9783Claims) Validate() error {
	// "baseline" validation of P2 claims
	if err := ValidateClaims(o); err != nil {
		return err
	}

	// additional validation: ensure bootseed is between 8 and 32 bytes if present
	if _, err := o.GetBootSeed(); err != nil && err != ErrOptionalClaimMissing {
		return err
	}

	return nil
}

func (o *RFC9783Claims) SetBootSeed(v []byte) error {
	l := len(v)
	if l < 8 || l > 32 {
		return fmt.Errorf(
			"%w: invalid length %d (MUST be between 8 and 32 bytes)",
			ErrWrongSyntax, l,
		)
	}

	o.BootSeed = &v

	return nil
}

func (o *RFC9783Claims) GetBootSeed() ([]byte, error) {
	if o.BootSeed == nil {
		return nil, ErrOptionalClaimMissing
	}

	l := len(*o.BootSeed)
	if l < 8 || l > 32 {
		return nil, fmt.Errorf(
			"%w: invalid length %d (MUST be between 8 and 32 bytes)",
			ErrWrongSyntax, l,
		)
	}

	return *o.BootSeed, nil
}

// To ensure embedding is handled correctly during marshaling, we need to use
// custom encoding functions, which means implementing the four marshaling
// methods defined by IClaims.

func (o RFC9783Claims) MarshalCBOR() ([]byte, error) { //nolint:gocritic
	return encoding.SerializeStructToCBOR(em, &o)
}

func (o *RFC9783Claims) UnmarshalCBOR(data []byte) error {
	return encoding.PopulateStructFromCBOR(dm, data, o)
}

func (o RFC9783Claims) MarshalJSON() ([]byte, error) { //nolint:gocritic
	return encoding.SerializeStructToJSON(&o)

}

func (o *RFC9783Claims) UnmarshalJSON(data []byte) error {
	return encoding.PopulateStructFromJSON(data, o)
}

// Name of the profile associated with RFC9783Claims
const RFC9783ProfileName = "tag:psacertified.org,2023:psa#tfm"

// factory function for RFC9783Claims
func NewRFC9783Claims() *RFC9783Claims {
	p := eat.Profile{}
	if err := p.Set(RFC9783ProfileName); err != nil {
		// should never get here as using known good constant as input
		panic(err)
	}

	return &RFC9783Claims{
		P2Claims: P2Claims{
			Profile: &p,

			// We need to provide an implementation of
			// ISwComponent; as we're not extending software
			// components, we're using the default implmentation
			SwComponents: &SwComponents[*SwComponent]{},

			// setting CanonicalProfile to our profile name, as we will be
			// relying on the P2Claims's implementation to validate
			// Profile claim,
			CanonicalProfile: RFC9783ProfileName,
		},
	}
}

// Implementation of IProfile. This is used to register the new IClaims
// implementation and associated it with the profile name.
type RFC9783Profile struct{}

func (o RFC9783Profile) GetName() string {
	return RFC9783ProfileName
}

func (o RFC9783Profile) GetClaims() IClaims {
	return NewRFC9783Claims()
}

// Registering the profile inside init() to ensure that it it is available to
// the general NewClaims() and DecodeClaims() functions, and the IClaims
// implementation associated with the profile will automatically be used when
// the profile in the data matches the registered name.
func init() {
	if err := RegisterProfile(RFC9783Profile{}); err != nil {
		panic(err)
	}
}
