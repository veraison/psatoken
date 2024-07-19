// Copyright 2021-2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package psatoken

import (
	"encoding/json"
	"errors"
	"fmt"
)

// IClaimsBase defines an interface for working with all EAT-based claims
type IClaimsBase interface {
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
// cannot rely on their existing Validate() methods.
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

// ValidateAndEncodeClaimsToCBOR returns a []byte containing CBOR-encoded
// IClaims that were provided as input. An error is returned instead if the
// provided claims are invalid or if the encoding fails.
func ValidateAndEncodeClaimsToCBOR(c IClaims) ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}

	return em.Marshal(c)
}

// EncodeClaimsToCBOR returns a []byte containing CBOR-encoded IClaims, or an
// error if encoding fails.
func EncodeClaimsToCBOR(c IClaims) ([]byte, error) {
	return em.Marshal(c)
}

// ValidateAndEncodeClaimsToJSON returns a []byte containing JSON-encoded
// IClaims that were provided as input. An error is returned instead if the
// provided claims are invalid or if the encoding fails.
func ValidateAndEncodeClaimsToJSON(c IClaims) ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}

	return json.Marshal(c)
}

// EncodeClaimsToJSON returns a []byte containing JSON-encoded IClaims, or an
// error if encoding fails.
func EncodeClaimsToJSON(c IClaims) ([]byte, error) {
	return json.Marshal(c)
}

// DecodeAndValidateClaimsFromCBOR returns an IClaims implementation instance populated
// from the provided CBOR buf. The implementation used is determined by value
// of the eat_profile (key 265) in the provided CBOR object. In the absence of
// this claim, Profile1 (PSA_IOT_PROFILE_1) is assumed. Claims are validated
// according to the profile as part of decoding.
func DecodeAndValidateClaimsFromCBOR(buf []byte) (IClaims, error) {
	claims, err := DecodeClaimsFromCBOR(buf)
	if err != nil {
		return nil, err
	}

	if err := claims.Validate(); err != nil {
		return nil, err
	}

	return claims, nil
}

// DecodeClaimsFromCBOR returns an IClaims implementation instance
// populated from the provided CBOR buf. The implementation used is determined
// by value of the eat_profile (key 265) in the provided CBOR object. In the
// absence of this key, Profile1 (PSA_IOT_PROFILE_1) is assumed. No validation
// is performed to confirm that the decoded claims actually conform to the
// stated profile.
func DecodeClaimsFromCBOR(buf []byte) (IClaims, error) {
	selector := struct {
		// note: code point 265 is defined as the eat_profile claim in
		// EAT(https://datatracker.ietf.org/doc/draft-ietf-rats-eat/).
		// This is not specific to PSA, and so is not something that we
		// expect PSA profiles to be able to override.
		// The only exception to this P1, which does not use the
		// eat_profile claim (code point 265). It instead defines its
		// own pofile at code point -7500. This will not be unmarshaled
		// into this field. For P1, the dm.Unmarshal below will leave
		// the field in its default value "" (however, it will not
		// result in an error). As the P1 profile field is optional, if
		// a profile is not present in the claims, they are assumed to
		// be for P1 (as that would make them automatically invalid for
		// any other profile). Because of this, the P1 claims will be
		// selected from the register if the Profile field here is
		// empty, and the decoding will proceed correctly. P1's -7500
		// profile field will then be validated as part of the full
		// claims decoding in UnmarshalCBOR() further down.
		Profile string `cbor:"265,keyasint"`
	}{}

	err := dm.Unmarshal(buf, &selector)
	if err != nil {
		return nil, err
	}

	entry, ok := profilesRegister[selector.Profile]
	if !ok {
		return nil, fmt.Errorf("unknown profile: %q", selector.Profile)
	}

	claims := entry.Profile.GetClaims()

	if err := dm.Unmarshal(buf, claims); err != nil {
		return nil, err
	}

	return claims, nil
}

// Deprecated: use DecodeAndValidateClaimsFromJSON instead.
func DecodeJSONClaims(buf []byte) (IClaims, error) {
	return DecodeAndValidateClaimsFromJSON(buf)
}

// DecodeAndValidateClaimsFromJSON returns an IClaims implementation instance populated
// from the provided JSON buf. The implementation used is determined by value
// of the profile field in the provided JSON object. In the absence of
// this field, Profile1 (PSA_IOT_PROFILE_1) is assumed. Claims are validated
// according to the profile as part of decoding.
func DecodeAndValidateClaimsFromJSON(buf []byte) (IClaims, error) {
	claims, err := DecodeClaimsFromJSON(buf)
	if err != nil {
		return nil, err
	}

	if err := claims.Validate(); err != nil {
		return nil, err
	}

	return claims, nil
}

// Deprecated: use DecodeClaimsFromJSON instead.
func DecodeUnvalidatedJSONClaims(buf []byte) (IClaims, error) {
	return DecodeClaimsFromJSON(buf)
}

// DecodeClaimsFromJSON returns an IClaims implementation instance
// populated from the provided JSON buf. The implementation used is determined
// by value of the profile field in the provided JSON object. In the absence
// of this field, Profile1 (PSA_IOT_PROFILE_1) is assumed. No validation is
// performed to confirm that the decoded claims actually conform to the stated
// profile.
func DecodeClaimsFromJSON(buf []byte) (IClaims, error) {
	var decoded map[string]interface{}
	if err := json.Unmarshal(buf, &decoded); err != nil {
		return nil, err
	}

	var found IProfile

	for name, entry := range profilesRegister {
		if profileTag, ok := decoded[entry.JSONTag]; ok {
			if profileTag != entry.Profile.GetName() {
				continue
			}

			if found != nil && found.GetName() != entry.Profile.GetName() {
				return nil, fmt.Errorf("matched multiple profiles: %s and %s",
					name, found.GetName())
			}

			found = entry.Profile
		}
	}

	if found == nil {
		return nil, errors.New(`could not match profile`)
	}

	claims := found.GetClaims()

	if err := json.Unmarshal(buf, claims); err != nil {
		return nil, err
	}

	return claims, nil
}
