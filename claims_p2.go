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

type Profile2 struct{}

func (o Profile2) GetName() string {
	return Profile2Name
}

func (o Profile2) GetClaims() IClaims {
	claims, err := newP2Claims()

	if err != nil {
		// We should never get here as the only source of error inside
		// newP2Claims() is when attempting to set the Profile field
		// when it is already set; however, as we're creating a new
		// claims struct, this cannot happen.
		panic(err)
	}

	return claims
}

// P2Claims are associated with profile "http://arm.com/psa/2.0.0"
type P2Claims struct {
	Profile                *eat.Profile   `cbor:"265,keyasint" json:"eat-profile"`
	ClientID               *int32         `cbor:"2394,keyasint" json:"psa-client-id"`
	SecurityLifeCycle      *uint16        `cbor:"2395,keyasint" json:"psa-security-lifecycle"`
	ImplID                 *[]byte        `cbor:"2396,keyasint" json:"psa-implementation-id"`
	BootSeed               *[]byte        `cbor:"2397,keyasint,omitempty" json:"psa-boot-seed,omitempty"`
	CertificationReference *string        `cbor:"2398,keyasint,omitempty" json:"psa-certification-reference,omitempty"`
	SwComponents           *[]SwComponent `cbor:"2399,keyasint" json:"psa-software-components"`
	Nonce                  *eat.Nonce     `cbor:"10,keyasint" json:"psa-nonce"`
	InstID                 *eat.UEID      `cbor:"256,keyasint" json:"psa-instance-id"`
	VSI                    *string        `cbor:"2400,keyasint,omitempty" json:"psa-verification-service-indicator,omitempty"`
}

func newP2Claims() (IClaims, error) {
	var c P2Claims

	if err := c.setProfile(); err != nil {
		return nil, err
	}

	return &c, nil
}

// Semantic validation
func (c P2Claims) Validate() error { //nolint:gocritic
	return ValidateClaims(&c)
}

func (c *P2Claims) setProfile() error {
	if c.Profile != nil {
		panic("profile already set")
	}

	p := eat.Profile{}

	if err := p.Set(Profile2Name); err != nil {
		return err
	}

	c.Profile = &p

	return nil
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
			ErrWrongClaimSyntax, l,
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
			ErrWrongClaimSyntax,
		)
	}

	c.CertificationReference = &v

	return nil
}

func (c *P2Claims) SetSoftwareComponents(scs []SwComponent) error {
	if err := ValidateSwComponents(scs); err != nil {
		return err
	}

	c.SwComponents = &scs

	return nil
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

func (c *P2Claims) FromCBOR(buf []byte) error {
	err := c.FromUnvalidatedCBOR(buf)
	if err != nil {
		return err
	}

	err = c.Validate()
	if err != nil {
		return fmt.Errorf("validation of PSA claims failed: %w", err)
	}

	return nil
}

func (c *P2Claims) FromUnvalidatedCBOR(buf []byte) error {
	err := dm.Unmarshal(buf, c)
	if err != nil {
		return fmt.Errorf("CBOR decoding of PSA claims failed: %w", err)
	}

	return nil
}

func (c P2Claims) ToCBOR() ([]byte, error) { //nolint:gocritic
	err := c.Validate()
	if err != nil {
		return nil, fmt.Errorf("validation of PSA claims failed: %w", err)
	}

	return c.ToUnvalidatedCBOR()
}

func (c P2Claims) ToUnvalidatedCBOR() ([]byte, error) { //nolint:gocritic
	buf, err := em.Marshal(&c)
	if err != nil {
		return nil, fmt.Errorf("CBOR encoding of PSA claims failed: %w", err)
	}

	return buf, nil
}

func (c *P2Claims) FromJSON(buf []byte) error {
	err := c.FromUnvalidatedJSON(buf)
	if err != nil {
		return err
	}

	err = c.Validate()
	if err != nil {
		return fmt.Errorf("validation of PSA claims failed: %w", err)
	}

	return nil
}

func (c *P2Claims) FromUnvalidatedJSON(buf []byte) error {
	err := json.Unmarshal(buf, c)
	if err != nil {
		return fmt.Errorf("JSON decoding of PSA claims failed: %w", err)
	}

	return nil
}

func (c P2Claims) ToJSON() ([]byte, error) { //nolint:gocritic
	err := c.Validate()
	if err != nil {
		return nil, fmt.Errorf("validation of PSA claims failed: %w", err)
	}

	return c.ToUnvalidatedJSON()
}

func (c P2Claims) ToUnvalidatedJSON() ([]byte, error) { //nolint:gocritic
	buf, err := json.Marshal(&c)
	if err != nil {
		return nil, fmt.Errorf("JSON encoding of PSA claims failed: %w", err)
	}

	return buf, nil
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

	if profileString != Profile2Name {
		return "", fmt.Errorf("%w: expecting %q, got %q",
			ErrWrongProfile, Profile2Name, profileString)
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
			ErrWrongClaimSyntax, l,
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
			ErrWrongClaimSyntax,
		)
	}

	return *c.CertificationReference, nil
}

func (c P2Claims) GetSoftwareComponents() ([]SwComponent, error) { //nolint:gocritic
	if c.SwComponents == nil {
		return nil, ErrMandatoryClaimMissing
	}

	if err := ValidateSwComponents(*c.SwComponents); err != nil {
		return nil, err
	}

	return *c.SwComponents, nil
}

func (c P2Claims) GetNonce() ([]byte, error) { //nolint:gocritic
	v := c.Nonce

	if v == nil {
		return nil, ErrMandatoryClaimMissing
	}

	l := v.Len()

	if l != 1 {
		return nil, fmt.Errorf("%w: got %d nonces, want 1", ErrWrongClaimSyntax, l)
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
