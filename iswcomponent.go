// Copyright 2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package psatoken

import "fmt"

// ISwComponent defines the interface for the software component composite
// claim.
type ISwComponent interface {
	Validate() error

	GetMeasurementType() (string, error)
	GetMeasurementValue() ([]byte, error)
	GetVersion() (string, error)
	GetSignerID() ([]byte, error)
	GetMeasurementDesc() (string, error)

	SetMeasurementType(v string) error
	SetMeasurementValue(v []byte) error
	SetVersion(v string) error
	SetSignerID(v []byte) error
	SetMeasurementDesc(v string) error
}

// ValidateSwComponent returns an error if validation fails for any of the
// fields of a software component claim. This function may be used by new
// ISwComponent implementations that do not embed existing SwComponent, and so
// cannot rely on its Validate() method.
func ValidateSwComponent(c ISwComponent) error {
	if err := FilterError(c.GetMeasurementType()); err != nil {
		return fmt.Errorf("measurement type: %w", err)
	}

	if err := FilterError(c.GetMeasurementValue()); err != nil {
		return fmt.Errorf("measurement value: %w", err)
	}

	if err := FilterError(c.GetVersion()); err != nil {
		return fmt.Errorf("version: %w", err)
	}

	if err := FilterError(c.GetSignerID()); err != nil {
		return fmt.Errorf("signer ID: %w", err)
	}

	if err := FilterError(c.GetMeasurementDesc()); err != nil {
		return fmt.Errorf("measurement description: %w", err)
	}

	return nil
}
