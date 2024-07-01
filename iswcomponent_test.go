// Copyright 2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package psatoken

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

type testSwComponent struct {
	MeasurementType  error
	MeasurementValue error
	Version          error
	SignerID         error
	MeasurementDesc  error
}

func (o *testSwComponent) GetMeasurementType() (string, error) {
	return "", o.MeasurementType
}

func (o *testSwComponent) GetMeasurementValue() ([]byte, error) {
	return nil, o.MeasurementValue
}

func (o *testSwComponent) GetVersion() (string, error) {
	return "", o.Version
}

func (o *testSwComponent) GetSignerID() ([]byte, error) {
	return nil, o.SignerID
}

func (o *testSwComponent) GetMeasurementDesc() (string, error) {
	return "", o.MeasurementDesc
}

func (o *testSwComponent) SetMeasurementType(v string) error  { return nil }
func (o *testSwComponent) SetMeasurementValue(v []byte) error { return nil }
func (o *testSwComponent) SetVersion(v string) error          { return nil }
func (o *testSwComponent) SetSignerID(v []byte) error         { return nil }
func (o *testSwComponent) SetMeasurementDesc(v string) error  { return nil }
func (o *testSwComponent) Validate() error                    { return nil }

func Test_ValidateSwComoponent(t *testing.T) {
	tvs := []struct {
		Name  string
		Value *testSwComponent
		Err   string
	}{
		{
			Name:  "ok",
			Value: &testSwComponent{},
			Err:   "",
		},
		{
			Name:  "nok measurement type",
			Value: &testSwComponent{MeasurementType: errors.New("bad")},
			Err:   "measurement type: bad",
		},
		{
			Name:  "nok measurement value",
			Value: &testSwComponent{MeasurementValue: errors.New("bad")},
			Err:   "measurement value: bad",
		},
		{
			Name:  "nok version",
			Value: &testSwComponent{Version: errors.New("bad")},
			Err:   "version: bad",
		},
		{
			Name:  "nok signer ID",
			Value: &testSwComponent{SignerID: errors.New("bad")},
			Err:   "signer ID: bad",
		},
		{
			Name:  "nok measurement desc",
			Value: &testSwComponent{MeasurementDesc: errors.New("bad")},
			Err:   "measurement description: bad",
		},
	}

	for _, tv := range tvs {
		t.Run(tv.Name, func(t *testing.T) {
			err := ValidateSwComponent(tv.Value)

			if tv.Err != "" {
				assert.EqualError(t, err, tv.Err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
