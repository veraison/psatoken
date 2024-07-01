// Copyright 2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package psatoken

type ISwComponents interface {
	Validate() error
	Values() ([]ISwComponent, error)
	Add(vals ...ISwComponent) error
	Replace(vals []ISwComponent) error
	IsEmpty() bool
}
