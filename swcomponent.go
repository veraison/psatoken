// Copyright 2021-2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package psatoken

// SwComponent is the internal representation of a Software Component
type SwComponent struct {
	MeasurementType  *string `cbor:"1,keyasint,omitempty" json:"measurement-type,omitempty"`
	MeasurementValue *[]byte `cbor:"2,keyasint" json:"measurement-value"`
	Version          *string `cbor:"4,keyasint,omitempty" json:"version,omitempty"`
	SignerID         *[]byte `cbor:"5,keyasint" json:"signer-id"`
	MeasurementDesc  *string `cbor:"6,keyasint,omitempty" json:"measurement-description,omitempty"`
}

func (sc SwComponent) Validate() error {
	return ValidateSwComponent(&sc)
}

func (sc SwComponent) GetMeasurementValue() ([]byte, error) {
	if sc.MeasurementValue == nil {
		return nil, ErrMandatoryFieldMissing
	}

	if err := ValidatePSAHashType(*sc.MeasurementValue); err != nil {
		return nil, err
	}

	return *sc.MeasurementValue, nil
}

func (sc SwComponent) GetSignerID() ([]byte, error) {
	if sc.SignerID == nil {
		return nil, ErrMandatoryFieldMissing
	}

	if err := ValidatePSAHashType(*sc.SignerID); err != nil {
		return nil, err
	}

	return *sc.SignerID, nil
}

func (sc SwComponent) GetMeasurementType() (string, error) {
	if sc.MeasurementType == nil {
		return "", ErrOptionalFieldMissing
	}

	return *sc.MeasurementType, nil
}

func (sc SwComponent) GetMeasurementDesc() (string, error) {
	if sc.MeasurementDesc == nil {
		return "", ErrOptionalFieldMissing
	}

	return *sc.MeasurementDesc, nil
}

func (sc SwComponent) GetVersion() (string, error) {
	if sc.Version == nil {
		return "", ErrOptionalFieldMissing
	}

	return *sc.Version, nil
}

func (sc *SwComponent) SetMeasurementType(v string) error {
	sc.MeasurementType = &v
	return nil
}

func (sc *SwComponent) SetMeasurementValue(v []byte) error {
	if err := ValidatePSAHashType(v); err != nil {
		return err
	}

	sc.MeasurementValue = &v

	return nil
}

func (sc *SwComponent) SetVersion(v string) error {
	sc.Version = &v
	return nil
}

func (sc *SwComponent) SetSignerID(v []byte) error {
	if err := ValidatePSAHashType(v); err != nil {
		return err
	}

	sc.SignerID = &v

	return nil
}

func (sc *SwComponent) SetMeasurementDesc(v string) error {
	sc.MeasurementDesc = &v
	return nil
}
