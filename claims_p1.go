// Copyright 2021-2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package psatoken

import (
	_ "crypto/sha256" // used hash algorithms need to be imported explicitly
	"encoding/json"
	"fmt"
)

type PSAProfile1 struct{}

func (o PSAProfile1) GetName() string {
	return "PSA_IOT_PROFILE_1"
}

func (o PSAProfile1) GetClaims() IClaims {
	claims, err := newP1Claims(true)

	if err != nil {
		// We should never get here as the only source of error inside
		// newP1Claims() is when attempting to set the Profile field
		// when it is already set; however, as we're crleating a new
		// claims struct, this cannot happen.
		panic(err)
	}

	return claims
}

// P1Claims are associated with profile "PSA_IOT_PROFILE_1"
type P1Claims struct {
	Profile                *string        `cbor:"-75000,keyasint,omitempty" json:"psa-profile"`
	ClientID               *int32         `cbor:"-75001,keyasint" json:"psa-client-id"`
	SecurityLifeCycle      *uint16        `cbor:"-75002,keyasint" json:"psa-security-lifecycle"`
	ImplID                 *[]byte        `cbor:"-75003,keyasint" json:"psa-implementation-id"`
	BootSeed               *[]byte        `cbor:"-75004,keyasint" json:"psa-boot-seed"`
	CertificationReference *string        `cbor:"-75005,keyasint,omitempty" json:"psa-hwver,omitempty"`
	SwComponents           *[]SwComponent `cbor:"-75006,keyasint,omitempty" json:"psa-software-components,omitempty"`
	NoSwMeasurements       *uint          `cbor:"-75007,keyasint,omitempty" json:"psa-no-software-measurements,omitempty"`
	Nonce                  *[]byte        `cbor:"-75008,keyasint" json:"psa-nonce"`
	InstID                 *[]byte        `cbor:"-75009,keyasint" json:"psa-instance-id"`
	VSI                    *string        `cbor:"-75010,keyasint,omitempty" json:"psa-verification-service-indicator,omitempty"`
}

func newP1Claims(includeProfile bool) (IClaims, error) {
	var c P1Claims

	if includeProfile {
		if err := c.setProfile(); err != nil {
			return nil, err
		}
	}

	return &c, nil
}

// Semantic validation
func (c P1Claims) Validate() error { //nolint:gocritic
	return validate(&c, PsaProfile1)
}

func (c *P1Claims) setProfile() error {
	if c.Profile != nil {
		panic("profile already set")
	}

	p := PsaProfile1

	c.Profile = &p

	return nil
}

func (c *P1Claims) SetClientID(v int32) error {
	return setClientID(&c.ClientID, &v)
}

func (c *P1Claims) SetSecurityLifeCycle(v uint16) error {
	return setSecurityLifeCycle(&c.SecurityLifeCycle, &v, PsaProfile1)
}

func (c *P1Claims) SetImplID(v []byte) error {
	return setImplID(&c.ImplID, &v)
}

func (c *P1Claims) SetBootSeed(v []byte) error {
	return setBootSeed(&c.BootSeed, &v, PsaProfile1)
}

func (c *P1Claims) SetCertificationReference(v string) error {
	return setCertificationReference(&c.CertificationReference, &v, PsaProfile1)
}

// pass scs==nil to set the no-sw-measurements flag
func (c *P1Claims) SetSoftwareComponents(scs []SwComponent) error {
	if scs == nil {
		v := uint(1)
		c.NoSwMeasurements = &v
		c.SwComponents = nil
		return nil
	}

	if err := isValidSwComponents(scs); err != nil {
		return err
	}

	c.SwComponents = &scs
	c.NoSwMeasurements = nil

	return nil
}

func (c *P1Claims) SetNonce(v []byte) error {
	if err := isPSAHashType(v); err != nil {
		return err
	}

	c.Nonce = &v

	return nil
}

func (c *P1Claims) SetInstID(v []byte) error {
	if err := isValidInstID(v); err != nil {
		return err
	}

	c.InstID = &v

	return nil
}

func (c *P1Claims) SetVSI(v string) error {
	return setVSI(&c.VSI, &v)
}

func (c *P1Claims) SetConfig(v []byte) error {
	return fmt.Errorf("invalid SetConfig invoked on p1 claims")
}

func (c *P1Claims) SetHashAlgID(v string) error {
	return fmt.Errorf("invalid SetHashAlgID invoked on p1 claims")
}

// Codecs

func (c *P1Claims) FromCBOR(buf []byte) error {
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

func (c *P1Claims) FromUnvalidatedCBOR(buf []byte) error {
	err := dm.Unmarshal(buf, c)
	if err != nil {
		return fmt.Errorf("CBOR decoding of PSA claims failed: %w", err)
	}

	return nil
}

func (c P1Claims) ToCBOR() ([]byte, error) { //nolint:gocritic
	err := c.Validate()
	if err != nil {
		return nil, fmt.Errorf("validation of PSA claims failed: %w", err)
	}

	return c.ToUnvalidatedCBOR()
}

func (c P1Claims) ToUnvalidatedCBOR() ([]byte, error) { //nolint:gocritic
	buf, err := em.Marshal(&c)
	if err != nil {
		return nil, fmt.Errorf("CBOR encoding of PSA claims failed: %w", err)
	}

	return buf, nil
}

func (c *P1Claims) FromJSON(buf []byte) error {
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

func (c *P1Claims) FromUnvalidatedJSON(buf []byte) error {
	err := json.Unmarshal(buf, c)
	if err != nil {
		return fmt.Errorf("JSON decoding of PSA claims failed: %w", err)
	}

	return nil
}

func (c P1Claims) ToJSON() ([]byte, error) { //nolint:gocritic
	err := c.Validate()
	if err != nil {
		return nil, fmt.Errorf("validation of PSA claims failed: %w", err)
	}

	return c.ToUnvalidatedJSON()
}

func (c P1Claims) ToUnvalidatedJSON() ([]byte, error) { //nolint:gocritic
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

func (c P1Claims) GetProfile() (string, error) { //nolint:gocritic
	if c.Profile == nil {
		return PsaProfile1, nil
	}

	return *c.Profile, nil
}

func (c P1Claims) GetClientID() (int32, error) { //nolint:gocritic
	return getClientID(c.ClientID)
}

func (c P1Claims) GetSecurityLifeCycle() (uint16, error) { //nolint:gocritic
	return getSecurityLifeCycle(c.SecurityLifeCycle, PsaProfile1)
}

func (c P1Claims) GetImplID() ([]byte, error) { //nolint:gocritic
	return getImplID(c.ImplID)
}

func (c P1Claims) GetBootSeed() ([]byte, error) { //nolint:gocritic
	return getBootSeed(c.BootSeed, PsaProfile1)
}

func (c P1Claims) GetCertificationReference() (string, error) { //nolint:gocritic
	return getCertificationReference(c.CertificationReference, PsaProfile1)
}

// Caveat: this may return nil on success if psa-no-sw-measurement is asserted
func (c P1Claims) GetSoftwareComponents() ([]SwComponent, error) { //nolint:gocritic
	v := c.SwComponents
	f := c.NoSwMeasurements

	if v == nil {
		// psa-no-sw-measurement must be asserted
		if f == nil {
			return nil, ErrMandatoryClaimMissing
		}
		return nil, nil
	}

	// psa-no-sw-measurement must not be asserted at the same time as psa-software-components
	if f != nil {
		return nil,
			fmt.Errorf(
				"%w: psa-no-sw-measurement and psa-software-components cannot be present at the same time",
				ErrWrongClaimSyntax,
			)
	}

	if err := isValidSwComponents(*v); err != nil {
		return nil, err
	}

	return *v, nil
}

func (c P1Claims) GetNonce() ([]byte, error) { //nolint:gocritic
	v := c.Nonce

	if v == nil {
		return nil, ErrMandatoryClaimMissing
	}

	if err := isValidNonce(*v); err != nil {
		return nil, err
	}

	return *v, nil
}

func (c P1Claims) GetInstID() ([]byte, error) { //nolint:gocritic
	v := c.InstID

	if v == nil {
		return nil, ErrMandatoryClaimMissing
	}

	if err := isValidInstID(*v); err != nil {
		return nil, err
	}

	return *v, nil
}

func (c P1Claims) GetVSI() (string, error) { //nolint:gocritic
	return getVSI(c.VSI)
}

func (c P1Claims) GetConfig() ([]byte, error) { //nolint:gocritic

	return nil, fmt.Errorf("invalid GetConfig invoked on p1 claims")
}

func (c P1Claims) GetHashAlgID() (string, error) { //nolint:gocritic

	return "", fmt.Errorf("invalid GetHashAlgID invoked on p1 claims")
}

func init() {
	if err := registerDefaultProfile(PSAProfile1{}); err != nil {
		panic(err)
	}

	if err := RegisterProfile(PSAProfile1{}); err != nil {
		panic(err)
	}
}
