// Copyright 2021-2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package psatoken

import (
	_ "crypto/sha256" // used hash algorithms need to be imported explicitly
	"encoding/json"
	"fmt"

	"github.com/veraison/eat"
)

const Profile2Name = "http://arm.com/psa/2.0.0"

// Profile2 provides the IClaims implementation associated with http://arm.com/psa/2.0.0
type Profile2 struct{}

func (o Profile2) GetName() string {
	return Profile2Name
}

func (o Profile2) GetClaims() IClaims {
	return newP2Claims()
}

// P2Claims are associated with profile "http://arm.com/psa/2.0.0"
// See https://datatracker.ietf.org/doc/html/draft-tschofenig-rats-psa-token-13
type P2Claims struct {
	Profile                *eat.Profile  `cbor:"265,keyasint" json:"eat-profile"`
	ClientID               *int32        `cbor:"2394,keyasint" json:"psa-client-id"`
	SecurityLifeCycle      *uint16       `cbor:"2395,keyasint" json:"psa-security-lifecycle"`
	ImplID                 *[]byte       `cbor:"2396,keyasint" json:"psa-implementation-id"`
	BootSeed               *[]byte       `cbor:"2397,keyasint,omitempty" json:"psa-boot-seed,omitempty"`
	CertificationReference *string       `cbor:"2398,keyasint,omitempty" json:"psa-certification-reference,omitempty"`
	SwComponents           ISwComponents `cbor:"2399,keyasint" json:"psa-software-components"`
	Nonce                  *eat.Nonce    `cbor:"10,keyasint" json:"psa-nonce"`
	InstID                 *eat.UEID     `cbor:"256,keyasint" json:"psa-instance-id"`
	VSI                    *string       `cbor:"2400,keyasint,omitempty" json:"psa-verification-service-indicator,omitempty"`

	// CanonicalProfile contains the "correct" profile name associated with
	// this IClaims implementation (e.g. "http://arm.com/psa/2.0.0" for
	// P2Claims). The reason this is a field rather than a global constant
	// is so that derived profiles can embed this struct and rely on its
	// existing validation methods.
	CanonicalProfile string `cbor:"-" json:"-"`
}

func newP2Claims() IClaims {
	p := eat.Profile{}
	if err := p.Set(Profile2Name); err != nil {
		// should never get here as using known good constant as input
		panic(err)
	}

	return &P2Claims{
		Profile:          &p,
		SwComponents:     &SwComponents[*SwComponent]{},
		CanonicalProfile: Profile2Name,
	}
}

// Semantic validation
func (c P2Claims) Validate() error { //nolint:gocritic
	return ValidateClaims(&c)
}

func (c *P2Claims) SetClientID(v int32) error {
	// any int32 value is acceptable
	c.ClientID = &v
	return nil
}

func (c *P2Claims) SetSecurityLifeCycle(v uint16) error {
	if err := ValidateSecurityLifeCycle(v); err != nil {
		return err
	}

	c.SecurityLifeCycle = &v

	return nil
}

func (c *P2Claims) SetImplID(v []byte) error {
	if err := ValidateImplID(v); err != nil {
		return err
	}

	c.ImplID = &v

	return nil
}

func (c *P2Claims) SetBootSeed(v []byte) error {
	l := len(v)
	if l < 8 || l > 32 {
		return fmt.Errorf(
			"%w: invalid length %d (MUST be between 8 and 32 bytes)",
			ErrWrongSyntax, l,
		)
	}

	c.BootSeed = &v

	return nil
}

func (c *P2Claims) SetCertificationReference(v string) error {
	if !CertificationReferenceP1RE.MatchString(v) &&
		!CertificationReferenceP2RE.MatchString(v) {
		return fmt.Errorf(
			"%w: MUST be in EAN-13 or EAN-13+5 format",
			ErrWrongSyntax,
		)
	}

	c.CertificationReference = &v

	return nil
}

func (c *P2Claims) SetSoftwareComponents(scs []ISwComponent) error {
	if c.SwComponents == nil {
		c.SwComponents = &SwComponents[*SwComponent]{}
	}

	return c.SwComponents.Replace(scs)
}

func (c *P2Claims) SetNonce(v []byte) error {
	if err := ValidatePSAHashType(v); err != nil {
		return err
	}

	n := eat.Nonce{}

	if err := n.Add(v); err != nil {
		return err
	}

	c.Nonce = &n

	return nil
}

func (c *P2Claims) SetInstID(v []byte) error {
	if err := ValidateInstID(v); err != nil {
		return err
	}

	ueid := eat.UEID(v)

	c.InstID = &ueid

	return nil
}

func (c *P2Claims) SetVSI(v string) error {
	if err := ValidateVSI(v); err != nil {
		return err
	}

	c.VSI = &v

	return nil
}

// Codecs

// this type alias is used to prevent infinite recursion during marshaling.
type p2Claims P2Claims

func (c *P2Claims) UnmarshalCBOR(buf []byte) error {
	c.Profile = nil // clear profile to make sure we take it from buf

	return dm.Unmarshal(buf, (*p2Claims)(c))
}

func (c *P2Claims) UnmarshalJSON(buf []byte) error {
	c.Profile = nil // clear profile to make sure we take it from buf

	return json.Unmarshal(buf, (*p2Claims)(c))
}

// Getters return a validated value or an error
// After successful call to Validate(), getters of mandatory claims are assured
// to never fail.  Getters of optional claim may still fail with
// ErrOptionalClaimMissing in case the claim is not present.

func (c P2Claims) GetProfile() (string, error) { //nolint:gocritic
	if c.Profile == nil {
		return "", ErrMandatoryClaimMissing
	}

	profileString, err := c.Profile.Get()
	if err != nil {
		return "", err
	}

	if profileString != c.CanonicalProfile {
		return "", fmt.Errorf("%w: expecting %q, got %q",
			ErrWrongProfile, c.CanonicalProfile, profileString)
	}

	return profileString, nil
}

func (c P2Claims) GetClientID() (int32, error) { //nolint:gocritic
	if c.ClientID == nil {
		return 0, ErrMandatoryClaimMissing
	}

	return *c.ClientID, nil
}

func (c P2Claims) GetSecurityLifeCycle() (uint16, error) { //nolint:gocritic
	if c.SecurityLifeCycle == nil {
		return 0, ErrMandatoryClaimMissing
	}

	if err := ValidateSecurityLifeCycle(*c.SecurityLifeCycle); err != nil {
		return 0, err
	}

	return *c.SecurityLifeCycle, nil
}

func (c P2Claims) GetImplID() ([]byte, error) { //nolint:gocritic
	if c.ImplID == nil {
		return nil, ErrMandatoryClaimMissing
	}

	if err := ValidateImplID(*c.ImplID); err != nil {
		return nil, err
	}

	return *c.ImplID, nil
}

func (c P2Claims) GetBootSeed() ([]byte, error) { //nolint:gocritic
	if c.BootSeed == nil {
		return nil, ErrOptionalClaimMissing
	}

	l := len(*c.BootSeed)
	if l < 8 || l > 32 {
		return nil, fmt.Errorf(
			"%w: invalid length %d (MUST be between 8 and 32 bytes)",
			ErrWrongSyntax, l,
		)
	}

	return *c.BootSeed, nil
}

func (c P2Claims) GetCertificationReference() (string, error) { //nolint:gocritic
	if c.CertificationReference == nil {
		return "", ErrOptionalClaimMissing
	}

	if !CertificationReferenceP2RE.MatchString(*c.CertificationReference) {
		return "", fmt.Errorf(
			"%w: MUST be in EAN-13+5 format",
			ErrWrongSyntax,
		)
	}

	return *c.CertificationReference, nil
}

func (c P2Claims) GetSoftwareComponents() ([]ISwComponent, error) { //nolint:gocritic
	if c.SwComponents == nil || c.SwComponents.IsEmpty() {
		return nil, fmt.Errorf("%w (MUST have at least one sw component)",
			ErrMandatoryClaimMissing)
	}

	return c.SwComponents.Values()
}

func (c P2Claims) GetNonce() ([]byte, error) { //nolint:gocritic
	v := c.Nonce

	if v == nil {
		return nil, ErrMandatoryClaimMissing
	}

	l := v.Len()

	if l != 1 {
		return nil, fmt.Errorf("%w: got %d nonces, want 1", ErrWrongSyntax, l)
	}

	n := v.GetI(0)
	if err := ValidateNonce(n); err != nil {
		return nil, err
	}

	return n, nil
}

func (c P2Claims) GetInstID() ([]byte, error) { //nolint:gocritic
	v := c.InstID

	if v == nil {
		return nil, ErrMandatoryClaimMissing
	}

	if err := ValidateInstID(*v); err != nil {
		return nil, err
	}

	return *v, nil
}

func (c P2Claims) GetVSI() (string, error) { //nolint:gocritic
	if c.VSI == nil {
		return "", ErrOptionalClaimMissing
	}

	if err := ValidateVSI(*c.VSI); err != nil {
		return "", err
	}

	return *c.VSI, nil
}

func init() {
	if err := RegisterProfile(Profile2{}); err != nil {
		panic(err)
	}
}
