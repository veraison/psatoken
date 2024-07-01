// Copyright 2021-2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package psatoken

import (
	"errors"
	"fmt"
)

var (
	ErrMissingOptional  = errors.New("missing optional")
	ErrMissingMandatory = errors.New("missing mandatory")
	ErrNotInProfile     = errors.New("not in profile")
	ErrWrongProfile     = errors.New("wrong profile")
	ErrWrongSyntax      = errors.New("wrong syntax")

	ErrOptionalClaimMissing  = fmt.Errorf("%w claim", ErrMissingOptional)
	ErrMandatoryClaimMissing = fmt.Errorf("%w claim", ErrMissingMandatory)
	ErrWrongClaimSyntax      = fmt.Errorf("%w for claim", ErrWrongSyntax)
	ErrClaimNotInProfile     = fmt.Errorf("claim %w", ErrNotInProfile)
)

// FilterError takes the output of IClaims getters and returns only the
// error, suppressing errors that do not indicate problems in the context of
// the IClaims' profile (i.e. missing optional claims, or claims not supported
// by the profile).
func FilterError(v interface{}, e error) error {
	if errors.Is(e, ErrMissingOptional) || errors.Is(e, ErrNotInProfile) {
		return nil
	}

	return e
}
