// Copyright 2021-2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package psatoken

import (
	"errors"
	"fmt"
)

// IClaims provides a uniform interface for dealing with claims in all supported
// profiles
type IClaims interface {
	// Getters
	GetProfile() (string, error)
	GetClientID() (int32, error)
	GetSecurityLifeCycle() (uint16, error)
	GetImplID() ([]byte, error)
	GetBootSeed() ([]byte, error)
	GetCertificationReference() (string, error)
	GetSoftwareComponents() ([]SwComponent, error)
	GetNonce() ([]byte, error)
	GetInstID() ([]byte, error)
	GetVSI() (string, error)
	GetConfig() ([]byte, error)
	GetHashAlgID() (string, error)

	// Setters
	SetClientID(int32) error
	SetSecurityLifeCycle(uint16) error
	SetImplID([]byte) error
	SetBootSeed([]byte) error
	SetCertificationReference(string) error
	SetSoftwareComponents([]SwComponent) error
	SetNonce([]byte) error
	SetInstID([]byte) error
	SetVSI(string) error
	SetConfig([]byte) error
	SetHashAlgID(string) error

	// CBOR codecs
	FromCBOR([]byte) error
	ToCBOR() ([]byte, error)

	// JSON codecs
	FromJSON([]byte) error
	ToJSON() ([]byte, error)

	// Semantic validation
	Validate() error
}

func NewClaims(profile string) (IClaims, error) {
	switch profile {
	case CcaProfile:
		return newCcaPlatformClaims()
	case PsaProfile1:
		includeProfileClaim := true
		return newP1Claims(includeProfileClaim)
	case PsaProfile2:
		return newP2Claims()
	default:
		return nil, fmt.Errorf("unsupported profile %q", profile)
	}
}

func DecodeClaims(buf []byte) (IClaims, error) {

	ccaPlat := &CcaPlatformClaims{}

	err3 := ccaPlat.FromCBOR(buf)
	if err3 == nil {
		return ccaPlat, nil
	}

	p2 := &P2Claims{}

	err2 := p2.FromCBOR(buf)
	if err2 == nil {
		return p2, nil
	}

	p1 := &P1Claims{}

	err1 := p1.FromCBOR(buf)
	if err1 == nil {
		return p1, nil
	}

	return nil, fmt.Errorf("decode failed for all CcaPlatform(%v), p1 (%v) and p2 (%v)", err3, err1, err2)
}

func DecodeJSONClaims(buf []byte) (IClaims, error) {

	ccaPlat := &CcaPlatformClaims{}

	err3 := ccaPlat.FromJSON(buf)
	if err3 == nil {
		return ccaPlat, nil
	}

	p2 := &P2Claims{}

	err2 := p2.FromJSON(buf)
	if err2 == nil {
		return p2, nil
	}

	p1 := &P1Claims{}

	err1 := p1.FromJSON(buf)
	if err1 == nil {
		return p1, nil
	}

	return nil, fmt.Errorf("JSON decode failed for all CcaPlatform(%v), p1 (%v) and p2 (%v)", err3, err1, err2)
}

func validate(c IClaims, profile string) error {
	p, err := c.GetProfile()
	if err != nil {
		return fmt.Errorf("validating profile: %w", err)
	}

	if p != profile {
		return fmt.Errorf("%w: expecting %q, got %q", ErrWrongProfile, profile, p)
	}

	// security lifecycle
	if _, err := c.GetSecurityLifeCycle(); err != nil {
		return fmt.Errorf("validating psa-security-lifecycle: %w", err)
	}

	// implementation id
	if _, err := c.GetImplID(); err != nil {
		return fmt.Errorf("validating psa-implementation-id: %w", err)
	}

	// sw components
	if _, err := c.GetSoftwareComponents(); err != nil {
		return fmt.Errorf("validating psa-software-components: %w", err)
	}

	// nonce
	if _, err := c.GetNonce(); err != nil {
		return fmt.Errorf("validating psa-nonce: %w", err)
	}

	// instance id
	if _, err := c.GetInstID(); err != nil {
		return fmt.Errorf("validating psa-instance-id: %w", err)
	}

	// VSI is optional
	if _, err := c.GetVSI(); err != nil && !errors.Is(err, ErrOptionalClaimMissing) {
		return fmt.Errorf("validating psa-verification-service-indicator: %w", err)
	}

	switch profile {
	case PsaProfile1, PsaProfile2:
		// client id
		if _, err := c.GetClientID(); err != nil {
			return fmt.Errorf("validating psa-client-id: %w", err)
		}

		// boot seed is optional in P2
		if _, err := c.GetBootSeed(); err != nil {
			if profile != PsaProfile2 ||
				(profile == PsaProfile2 && !errors.Is(err, ErrOptionalClaimMissing)) {
				return fmt.Errorf("validating psa-boot-seed: %w", err)
			}
		}

		// certification reference is optional
		if _, err := c.GetCertificationReference(); err != nil && !errors.Is(err, ErrOptionalClaimMissing) {
			return fmt.Errorf("validating psa-certification-reference: %w", err)
		}

	case CcaProfile:
		// config is mandatory in CCA
		if _, err := c.GetConfig(); err != nil {
			return fmt.Errorf("validating cca-platform-config: %w", err)
		}

		// hash algo id is mandatory in CCA
		if _, err := c.GetHashAlgID(); err != nil {
			return fmt.Errorf("validating cca-platform-hash-algo-id: %w", err)
		}
	}
	return nil
}
