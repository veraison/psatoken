// Copyright 2021-2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package psatoken

import "errors"

var (
	ErrClaimUndefined        = errors.New("undefined claim")
	ErrOptionalClaimMissing  = errors.New("missing optional claim")
	ErrMandatoryClaimMissing = errors.New("missing mandatory claim")
	ErrWrongClaimSyntax      = errors.New("wrong syntax for claim")
	ErrWrongProfile          = errors.New("wrong profile")
)
