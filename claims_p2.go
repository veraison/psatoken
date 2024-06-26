// Copyright 2021-2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package psatoken

import (
	_ "crypto/sha256" // used hash algorithms need to be imported explicitly
	"encoding/json"
	"fmt"

	"github.com/veraison/eat"
)

type PSAProfile2 struct{}

func (o PSAProfile2) GetName() string {
	return "http://arm.com/psa/2.0.0"
}

func (o PSAProfile2) GetClaims() IClaims {
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
	return validate(&c, PsaProfile2)
}

func (c *P2Claims) setProfile() error {
	if c.Profile != nil {
		panic("profile already set")
	}

	p := eat.Profile{}

	if err := p.Set(PsaProfile2); err != nil {
		return err
	}

	c.Profile = &p

	return nil
}

func (c *P2Claims) SetClientID(v int32) error {
	return setClientID(&c.ClientID, &v)
}

func (c *P2Claims) SetSecurityLifeCycle(v uint16) error {
	return setSecurityLifeCycle(&c.SecurityLifeCycle, &v, PsaProfile2)
}

func (c *P2Claims) SetImplID(v []byte) error {
	return setImplID(&c.ImplID, &v)
}

func (c *P2Claims) SetBootSeed(v []byte) error {
	return setBootSeed(&c.BootSeed, &v, PsaProfile2)
}

func (c *P2Claims) SetCertificationReference(v string) error {
	return setCertificationReference(&c.CertificationReference, &v, PsaProfile2)
}

func (c *P2Claims) SetSoftwareComponents(scs []SwComponent) error {
	if err := isValidSwComponents(scs); err != nil {
		return err
	}

	c.SwComponents = &scs

	return nil
}

func (c *P2Claims) SetNonce(v []byte) error {
	if err := isPSAHashType(v); err != nil {
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
	if err := isValidInstID(v); err != nil {
		return err
	}

	ueid := eat.UEID(v)

	c.InstID = &ueid

	return nil
}

func (c *P2Claims) SetVSI(v string) error {
	return setVSI(&c.VSI, &v)
}

func (c *P2Claims) SetConfig(v []byte) error {
	return fmt.Errorf("invalid SetConfig invoked on p2 claims")
}

func (c *P2Claims) SetHashAlgID(v string) error {
	return fmt.Errorf("invalid SetHashAlgID invoked on p2 claims")
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

	return c.Profile.Get()
}

func (c P2Claims) GetClientID() (int32, error) { //nolint:gocritic
	return getClientID(c.ClientID)
}

func (c P2Claims) GetSecurityLifeCycle() (uint16, error) { //nolint:gocritic
	return getSecurityLifeCycle(c.SecurityLifeCycle, PsaProfile2)
}

func (c P2Claims) GetImplID() ([]byte, error) { //nolint:gocritic
	return getImplID(c.ImplID)
}

func (c P2Claims) GetBootSeed() ([]byte, error) { //nolint:gocritic
	return getBootSeed(c.BootSeed, PsaProfile2)
}

func (c P2Claims) GetCertificationReference() (string, error) { //nolint:gocritic
	return getCertificationReference(c.CertificationReference, PsaProfile2)
}

func (c P2Claims) GetSoftwareComponents() ([]SwComponent, error) { //nolint:gocritic
	v := c.SwComponents

	if v == nil {
		return nil, ErrMandatoryClaimMissing
	}

	if err := isValidSwComponents(*v); err != nil {
		return nil, err
	}

	return *v, nil
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
	if err := isValidNonce(n); err != nil {
		return nil, err
	}

	return n, nil
}

func (c P2Claims) GetInstID() ([]byte, error) { //nolint:gocritic
	v := c.InstID

	if v == nil {
		return nil, ErrMandatoryClaimMissing
	}

	if err := isValidInstID(*v); err != nil {
		return nil, err
	}

	return *v, nil
}

func (c P2Claims) GetVSI() (string, error) { //nolint:gocritic
	return getVSI(c.VSI)
}

func (c P2Claims) GetConfig() ([]byte, error) { //nolint:gocritic
	return nil, fmt.Errorf("invalid GetConfig invoked on p2 claims")
}

func (c P2Claims) GetHashAlgID() (string, error) { //nolint:gocritic
	return "", fmt.Errorf("invalid GetHashAlgID invoked on p2 claims")
}

func init() {
	if err := RegisterProfile(PSAProfile2{}); err != nil {
		panic(err)
	}
}
