// Copyright 2021-2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package psatoken

import "fmt"

// IClaimsBase defines an interface for working with all EAT-based claims
type IClaimsBase interface {
	// CBOR codecs
	FromCBOR([]byte) error
	ToCBOR() ([]byte, error)
	FromUnvalidatedCBOR([]byte) error
	ToUnvalidatedCBOR() ([]byte, error)

	// JSON codecs
	FromJSON([]byte) error
	ToJSON() ([]byte, error)
	FromUnvalidatedJSON([]byte) error
	ToUnvalidatedJSON() ([]byte, error)

	// Semantic validation
	Validate() error
}

// IClaims defines a uniform interface for dealing with claims common to all
// PSA profiles
type IClaims interface {
	IClaimsBase

	GetProfile() (string, error)
	GetClientID() (int32, error)
	GetSecurityLifeCycle() (uint16, error)
	GetImplID() ([]byte, error)
	GetBootSeed() ([]byte, error)
	GetCertificationReference() (string, error)
	GetSoftwareComponents() ([]ISwComponent, error)
	GetNonce() ([]byte, error)
	GetInstID() ([]byte, error)
	GetVSI() (string, error)

	SetClientID(int32) error
	SetSecurityLifeCycle(uint16) error
	SetImplID([]byte) error
	SetBootSeed([]byte) error
	SetCertificationReference(string) error
	SetSoftwareComponents([]ISwComponent) error
	SetNonce([]byte) error
	SetInstID([]byte) error
	SetVSI(string) error
}

// NewClaims returns a new IClaims implementation instance associated with the
// specified profile name. An error is returned if the specified name does not
// correspond to any of the previously registered profiles.
func NewClaims(profile string) (IClaims, error) {
	entry, ok := profilesRegister[profile]
	if !ok {
		return nil, fmt.Errorf("unsupported profile %q", profile)
	}

	return entry.Profile.GetClaims(), nil
}

// ValidateClaims returns an error if validation fails for any of the standard
// PSA cliams defined by IClaims. This function may be used by new profiles
// whos implementations do not embed existing IClaims implementations and so
// cannot benefit from their existing Validate() methods.
func ValidateClaims(c IClaims) error {
	if err := FilterError(c.GetProfile()); err != nil {
		return fmt.Errorf("validating profile: %w", err)
	}

	if err := FilterError(c.GetSecurityLifeCycle()); err != nil {
		return fmt.Errorf("validating security lifecycle: %w", err)
	}

	if err := FilterError(c.GetImplID()); err != nil {
		return fmt.Errorf("validating implementation id: %w", err)
	}

	if err := FilterError(c.GetSoftwareComponents()); err != nil {
		return fmt.Errorf("validating software components: %w", err)
	}

	if err := FilterError(c.GetNonce()); err != nil {
		return fmt.Errorf("validating nonce: %w", err)
	}

	if err := FilterError(c.GetInstID()); err != nil {
		return fmt.Errorf("validating instance id: %w", err)
	}

	if err := FilterError(c.GetVSI()); err != nil {
		return fmt.Errorf("validating verification service indicator: %w", err)
	}

	if err := FilterError(c.GetClientID()); err != nil {
		return fmt.Errorf("validating client id: %w", err)
	}

	if err := FilterError(c.GetBootSeed()); err != nil {
		return fmt.Errorf("validating boot seed: %w", err)
	}

	if err := FilterError(c.GetCertificationReference()); err != nil {
		return fmt.Errorf("validating certification reference: %w", err)
	}

	return nil
}
