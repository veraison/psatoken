// Copyright 2021-2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package psatoken

import (
	_ "crypto/sha256" // used hash algorithms need to be imported explicitly
	"encoding/json"
	"fmt"
)

const Profile1Name = "PSA_IOT_PROFILE_1"

type Profile1 struct{}

func (o Profile1) GetName() string {
	return Profile1Name
}

func (o Profile1) GetClaims() IClaims {
	return newP1Claims(true)
}

// P1Claims are associated with profile "PSA_IOT_PROFILE_1"
type P1Claims struct {
	Profile                *string       `cbor:"-75000,keyasint,omitempty" json:"psa-profile"`
	ClientID               *int32        `cbor:"-75001,keyasint" json:"psa-client-id"`
	SecurityLifeCycle      *uint16       `cbor:"-75002,keyasint" json:"psa-security-lifecycle"`
	ImplID                 *[]byte       `cbor:"-75003,keyasint" json:"psa-implementation-id"`
	BootSeed               *[]byte       `cbor:"-75004,keyasint" json:"psa-boot-seed"`
	CertificationReference *string       `cbor:"-75005,keyasint,omitempty" json:"psa-hwver,omitempty"`
	SwComponents           ISwComponents `cbor:"-75006,keyasint,omitempty" json:"psa-software-components,omitempty"`
	NoSwMeasurements       *uint         `cbor:"-75007,keyasint,omitempty" json:"psa-no-software-measurements,omitempty"`
	Nonce                  *[]byte       `cbor:"-75008,keyasint" json:"psa-nonce"`
	InstID                 *[]byte       `cbor:"-75009,keyasint" json:"psa-instance-id"`
	VSI                    *string       `cbor:"-75010,keyasint,omitempty" json:"psa-verification-service-indicator,omitempty"`

	CanonicalProfile string `cbor:"-" json:"-"`
}

func newP1Claims(includeProfile bool) IClaims {
	if includeProfile {
		profile := Profile1Name
		return &P1Claims{
			Profile:          &profile,
			SwComponents:     &SwComponents[*SwComponent]{},
			CanonicalProfile: Profile1Name,
		}
	}

	return &P1Claims{
		SwComponents:     &SwComponents[*SwComponent]{},
		CanonicalProfile: Profile1Name,
	}
}

func (c P1Claims) Validate() error { //nolint:gocritic
	return ValidateClaims(&c)
}

func (c *P1Claims) SetClientID(v int32) error {
	c.ClientID = &v
	return nil
}

func (c *P1Claims) SetSecurityLifeCycle(v uint16) error {
	if err := ValidateSecurityLifeCycle(v); err != nil {
		return err
	}

	c.SecurityLifeCycle = &v

	return nil
}

func (c *P1Claims) SetImplID(v []byte) error {
	if err := ValidateImplID(v); err != nil {
		return err
	}

	c.ImplID = &v

	return nil
}

func (c *P1Claims) SetBootSeed(v []byte) error {
	l := len(v)
	if l != 32 {
		return fmt.Errorf(
			"%w: invalid length %d (MUST be 32 bytes)",
			ErrWrongSyntax, l,
		)
	}

	c.BootSeed = &v

	return nil
}

func (c *P1Claims) SetCertificationReference(v string) error {
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

// pass scs==nil to set the no-sw-measurements flag
func (c *P1Claims) SetSoftwareComponents(scs []ISwComponent) error {
	if scs == nil {
		v := uint(1)
		c.NoSwMeasurements = &v
		c.SwComponents = nil
		return nil
	}

	if c.SwComponents == nil {
		c.SwComponents = &SwComponents[*SwComponent]{}
	}

	if err := c.SwComponents.Replace(scs); err != nil {
		return err
	}

	c.NoSwMeasurements = nil

	return nil
}

func (c *P1Claims) SetNonce(v []byte) error {
	if err := ValidatePSAHashType(v); err != nil {
		return err
	}

	c.Nonce = &v

	return nil
}

func (c *P1Claims) SetInstID(v []byte) error {
	if err := ValidateInstID(v); err != nil {
		return err
	}

	c.InstID = &v

	return nil
}

func (c *P1Claims) SetVSI(v string) error {
	if err := ValidateVSI(v); err != nil {
		return err
	}

	c.VSI = &v

	return nil
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
	c.Profile = nil // clear profile to make sure we take it from buf

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
	var scs ISwComponents
	if c.SwComponents != nil && c.SwComponents.IsEmpty() {
		scs = c.SwComponents
		c.SwComponents = nil
	}

	buf, err := em.Marshal(&c)
	if scs != nil {
		c.SwComponents = scs
	}
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
	c.Profile = nil // clear profile to make sure we take it from buf

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
	var scs ISwComponents
	if c.SwComponents != nil && c.SwComponents.IsEmpty() {
		scs = c.SwComponents
		c.SwComponents = nil
	}

	buf, err := json.Marshal(&c)
	if scs != nil {
		c.SwComponents = scs
	}
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
		return c.CanonicalProfile, nil
	}

	p := *c.Profile

	if p != c.CanonicalProfile {
		return "", fmt.Errorf("%w: expecting %q, got %q", ErrWrongProfile, c.CanonicalProfile, p)
	}

	return p, nil
}

func (c P1Claims) GetClientID() (int32, error) { //nolint:gocritic
	if c.ClientID == nil {
		return 0, ErrMandatoryClaimMissing
	}

	return *c.ClientID, nil
}

func (c P1Claims) GetSecurityLifeCycle() (uint16, error) { //nolint:gocritic
	if c.SecurityLifeCycle == nil {
		return 0, ErrMandatoryClaimMissing
	}

	if err := ValidateSecurityLifeCycle(*c.SecurityLifeCycle); err != nil {
		return 0, err
	}

	return *c.SecurityLifeCycle, nil
}

func (c P1Claims) GetImplID() ([]byte, error) { //nolint:gocritic
	if c.ImplID == nil {
		return nil, ErrMandatoryClaimMissing
	}

	if err := ValidateImplID(*c.ImplID); err != nil {
		return nil, err
	}

	return *c.ImplID, nil
}

func (c P1Claims) GetBootSeed() ([]byte, error) { //nolint:gocritic
	if c.BootSeed == nil {
		return nil, ErrMandatoryClaimMissing
	}

	l := len(*c.BootSeed)
	if l != 32 {
		return nil, fmt.Errorf(
			"%w: invalid length %d (MUST be 32 bytes)",
			ErrWrongSyntax, l,
		)
	}

	return *c.BootSeed, nil
}

func (c P1Claims) GetCertificationReference() (string, error) { //nolint:gocritic
	if c.CertificationReference == nil {
		return "", ErrOptionalClaimMissing
	}

	if !CertificationReferenceP1RE.MatchString(*c.CertificationReference) &&
		!CertificationReferenceP2RE.MatchString(*c.CertificationReference) {
		return "", fmt.Errorf(
			"%w: MUST be in EAN-13 or EAN-13+5 format",
			ErrWrongSyntax,
		)
	}

	return *c.CertificationReference, nil
}

// Caveat: this may return nil on success if psa-no-sw-measurement is asserted
func (c P1Claims) GetSoftwareComponents() ([]ISwComponent, error) { //nolint:gocritic
	if c.SwComponents == nil || c.SwComponents.IsEmpty() {
		// psa-no-sw-measurement must be asserted
		if c.NoSwMeasurements == nil {
			return nil, fmt.Errorf("%w (MUST have at least one sw component or no-sw-measurements set)",
				ErrMandatoryClaimMissing)
		}
		return nil, nil
	}

	// psa-no-sw-measurement must not be asserted at the same time as psa-software-components
	if c.NoSwMeasurements != nil {
		return nil,
			fmt.Errorf(
				"%w: psa-no-sw-measurement and psa-software-components cannot be present at the same time",
				ErrWrongSyntax,
			)
	}

	return c.SwComponents.Values()
}

func (c P1Claims) GetNonce() ([]byte, error) { //nolint:gocritic
	if c.Nonce == nil {
		return nil, ErrMandatoryClaimMissing
	}

	if err := ValidateNonce(*c.Nonce); err != nil {
		return nil, err
	}

	return *c.Nonce, nil
}

func (c P1Claims) GetInstID() ([]byte, error) { //nolint:gocritic
	if c.InstID == nil {
		return nil, ErrMandatoryClaimMissing
	}

	if err := ValidateInstID(*c.InstID); err != nil {
		return nil, err
	}

	return *c.InstID, nil
}

func (c P1Claims) GetVSI() (string, error) { //nolint:gocritic
	if c.VSI == nil {
		return "", ErrOptionalClaimMissing
	}

	if err := ValidateVSI(*c.VSI); err != nil {
		return "", err
	}

	return *c.VSI, nil
}

func init() {
	if err := registerDefaultProfile(Profile1{}); err != nil {
		panic(err)
	}

	if err := RegisterProfile(Profile1{}); err != nil {
		panic(err)
	}
}
