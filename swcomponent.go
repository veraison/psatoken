// Copyright 2021-2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package psatoken

import (
	"errors"
	"fmt"
)

// SwComponent is the internal representation of a Software Component
type SwComponent struct {
	MeasurementType  *string `cbor:"1,keyasint,omitempty" json:"measurement-type,omitempty"`
	MeasurementValue *[]byte `cbor:"2,keyasint" json:"measurement-value"`
	Version          *string `cbor:"4,keyasint,omitempty" json:"version,omitempty"`
	SignerID         *[]byte `cbor:"5,keyasint" json:"signer-id"`
	MeasurementDesc  *string `cbor:"6,keyasint,omitempty" json:"measurement-description,omitempty"`
}

func (sc SwComponent) Validate() error {
	if sc.MeasurementValue == nil {
		return errors.New("missing mandatory measurement-value")
	}

	if err := isPSAHashType(*sc.MeasurementValue); err != nil {
		return fmt.Errorf("invalid measurement-value: %w", err)
	}

	if sc.SignerID == nil {
		return errors.New("missing mandatory signer-id")
	}

	if err := isPSAHashType(*sc.SignerID); err != nil {
		return fmt.Errorf("invalid signer-id: %w", err)
	}

	return nil
}

func (sc SwComponent) GetMeasurementValue() ([]byte, error) {
	if sc.MeasurementValue == nil {
		return nil, ErrMandatoryClaimMissing
	}

	return *sc.MeasurementValue, nil
}

func (sc SwComponent) GetSignerID() ([]byte, error) {
	if sc.SignerID == nil {
		return nil, ErrMandatoryClaimMissing
	}

	return *sc.SignerID, nil
}

func (sc SwComponent) GetMeasurementType() (string, error) {
	if sc.MeasurementType == nil {
		return "", ErrOptionalClaimMissing
	}

	return *sc.MeasurementType, nil
}

func (sc SwComponent) GetMeasurementDesc() (string, error) {
	if sc.MeasurementDesc == nil {
		return "", ErrOptionalClaimMissing
	}

	return *sc.MeasurementDesc, nil
}

func (sc SwComponent) GetVersion() (string, error) {
	if sc.Version == nil {
		return "", ErrOptionalClaimMissing
	}

	return *sc.Version, nil
}
