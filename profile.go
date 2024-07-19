// Copyright 2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package psatoken

import (
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
