// Copyright 2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package psatoken

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/veraison/psatoken/encoding"
)

// IProfile defines a way of obtaining an implementation of IClaims that
// corresponds to a particular profiles of a PSA token. A profile can
// - define the CBOR and JSON keys used for the claims defined by IClaims
// - indicate which claims are optional and which are mandatory
// - define extra claims in addition to the ones defined by IClaims
// - disallow some of the claims defined by IClaims
// Essentially, a Profile fully defines a concrete implementation of IClaims.
// This library provides two "base" PSA profile implementations: Profile1 and
// Profile2, corresponding to  PSA_IOT_PROFILE_1 and http://arm.com/psa/2.0.0
// respectively.
type IProfile interface {
	// GetName returns the name of this profile.
	GetName() string
	// GetClaims returns a new instance of the IClaims implementation
	// associated with this profile.
	GetClaims() IClaims
}

// RegisterProfile adds the provided IProfile implementation to the global
// register which is used by DecodeClaimsFromCBOR and DecodeClaimsFromJSON.
// An error is returned if a profile with an identical name is already
// registered.
func RegisterProfile(p IProfile) error {
	return registerProfileUnderName(p.GetName(), p)
}

// Deprecated: use DecodeClaimsFromCBOR instead.
func DecodeClaims(buf []byte) (IClaims, error) {
	return DecodeClaimsFromCBOR(buf)
}

// DecodeClaimsFromCBOR returns an IClaims implementation instance populated
// from the provided CBOR buf. The implementation used is determined by value
// of the eat_profile (key 265) in the provided CBOR object. In the absence of
// this claim, Profile1 (PSA_IOT_PROFILE_1) is assumed. Claims are validated
// according to the profile as part of decoding.
func DecodeClaimsFromCBOR(buf []byte) (IClaims, error) {
	claims, err := DecodeUnvalidatedClaimsFromCBOR(buf)
	if err != nil {
		return nil, err
	}

	if err := claims.Validate(); err != nil {
		return nil, err
	}

	return claims, nil
}

// Deprecated: use DecodeUnvalidatedClaimsFromCBOR instead.
func DecodeUnvalidatedClaims(buf []byte) (IClaims, error) {
	return DecodeUnvalidatedClaimsFromCBOR(buf)
}

// DecodeUnvalidatedClaimsFromCBOR returns an IClaims implementation instance
// populated from the provided CBOR buf. The implementation used is determined
// by value of the eat_profile (key 265) in the provided CBOR object. In the
// absence of this key, Profile1 (PSA_IOT_PROFILE_1) is assumed. No validation
// is performed to confirm that the decoded claims actually conform to the
// stated profile.
func DecodeUnvalidatedClaimsFromCBOR(buf []byte) (IClaims, error) {
	selector := struct {
		// note: code point 265 is defined as the eat_profile claim in
		// EAT(https://datatracker.ietf.org/doc/draft-ietf-rats-eat/).
		// This is not specific to PSA, and so is not something that we
		// expect PSA profiles to be able to override.
		// The only exception to this P1, which does not use the
		// eat_profile claim (code point 265). It instead defines its
		// own pofile at code point -7500. This will not be unmarshaled
		// into this field. For P1, the dm.Unmarshal below will leave
		// the field in its default value "" (however, it not result in
		// an error). As the P1 profile field is optional, if a profile
		// is not present in the claims, they are assumed to be for P1
		// (as that would make them automatically invalid for any other
		// profile). Because of this, the P1 claims will be selected
		// from the register if the Profile field here is empty, and
		// the decoding will proceed correctly. P1's -7500 profile
		// field will then be validated as part of the full claims
		// decoding in FromUnvalidatedCBOR() further down.
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

	if err := claims.FromUnvalidatedCBOR(buf); err != nil {
		return nil, err
	}

	return claims, nil
}

// Deprecated: use DecodeClaimsFromJSON instead.
func DecodeJSONClaims(buf []byte) (IClaims, error) {
	return DecodeClaimsFromJSON(buf)
}

// DecodeClaimsFromJSON returns an IClaims implementation instance populated
// from the provided JSON buf. The implementation used is determined by value
// of the profile field in the provided JSON object. In the absence of
// this field, Profile1 (PSA_IOT_PROFILE_1) is assumed. Claims are validated
// according to the profile as part of decoding.
func DecodeClaimsFromJSON(buf []byte) (IClaims, error) {
	claims, err := DecodeUnvalidatedClaimsFromJSON(buf)
	if err != nil {
		return nil, err
	}

	if err := claims.Validate(); err != nil {
		return nil, err
	}

	return claims, nil
}

// Deprecated: use DecodeUnvalidatedClaimsFromJSON instead.
func DecodeUnvalidatedJSONClaims(buf []byte) (IClaims, error) {
	return DecodeUnvalidatedClaimsFromJSON(buf)
}

// DecodeUnvalidatedClaimsFromJSON returns an IClaims implementation instance
// populated from the provided JSON buf. The implementation used is determined
// by value of the profile field in the provided JSON object. In the absence
// of this field, Profile1 (PSA_IOT_PROFILE_1) is assumed. No validation is
// performed to confirm that the decoded claims actually conform to the stated
// profile.
func DecodeUnvalidatedClaimsFromJSON(buf []byte) (IClaims, error) {
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

	if err := claims.FromUnvalidatedJSON(buf); err != nil {
		return nil, err
	}

	return claims, nil
}

type profileEntry struct {
	Profile IProfile
	JSONTag string
}

var profilesRegister = map[string]profileEntry{}

func registerDefaultProfile(p IProfile) error {
	return registerProfileUnderName("", p)
}

func registerProfileUnderName(name string, profile IProfile) error {
	if _, ok := profilesRegister[name]; ok {
		return fmt.Errorf("profile %q already registered", name)
	}

	tag, err := encoding.GetProfileJSONTag(profile.GetClaims())
	if err != nil {
		return fmt.Errorf("could not identify JSON tag for Profile field: %w", err)
	}

	profilesRegister[name] = profileEntry{Profile: profile, JSONTag: tag}

	return nil
}
