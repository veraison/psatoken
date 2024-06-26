// Copyright 2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package psatoken

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
)

type IProfile interface {
	GetName() string
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

	tag, err := getJSONTag(profile.GetClaims())
	if err != nil {
		return fmt.Errorf("could not identify JSON tag for Profile field: %w", err)
	}

	profilesRegister[name] = profileEntry{Profile: profile, JSONTag: tag}

	return nil
}

// getJSONTag returns the json tag associated with th profile field. The field
// is identified by the corresponding CBOR tag, or, if an appropriate CBOR tag is
// not found, by the field name.
func getJSONTag(iface interface{}) (string, error) {
	structType := reflect.TypeOf(iface)
	structVal := reflect.ValueOf(iface)

	if structType.Kind() == reflect.Pointer {
		structType = structType.Elem()
		structVal = structVal.Elem()
	}

	var foundByCBORKey *reflect.StructField
	var foundByFieldName *reflect.StructField

	for i := 0; i < structVal.NumField(); i++ {
		typeField := structType.Field(i)

		cborTag, ok := typeField.Tag.Lookup("cbor")
		if ok {
			cborKey := strings.Split(cborTag, ",")[0]
			if cborKey == "265" || cborKey == "-75000" { // eat_profile or psa-profile
				foundByCBORKey = &typeField
				break
			}
		} else if typeField.Name == "Profile" {
			foundByFieldName = &typeField
			// note: not breaking here as there could be
			// the CBOR profile tag in a later field, and
			// we want to use that in preference to the
			// field name.
		}

	}

	var jsonTag string
	var ok bool

	if foundByCBORKey != nil {
		jsonTag, ok = foundByCBORKey.Tag.Lookup("json")
	} else if foundByFieldName != nil {
		jsonTag, ok = foundByFieldName.Tag.Lookup("json")
	} else {
		return "", errors.New("could not identify profile field")
	}

	if !ok {
		return "", errors.New(`no "json" tag associated with profile field`)
	}

	return strings.Split(jsonTag, ",")[0], nil
}
