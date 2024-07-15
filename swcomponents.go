// Copyright 2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package psatoken

import (
	"encoding/json"
	"fmt"
	"reflect"
)

// SwComponents is the generic implementation of ISwComponents interface that
// should suffice for most purposes. This provides a container of concrete
// types for marashaling purposes (we can't unmarshal a slice of interfaces,
// such as []ISwComponent, with specifying a concrete type to use).
type SwComponents[I ISwComponent] struct {
	values []I // nolint:structcheck
}

func (o SwComponents[I]) Validate() error {
	for i, sc := range o.values {
		if err := sc.Validate(); err != nil {
			return fmt.Errorf("failed at index %d: %w", i, err)
		}
	}

	return nil
}

func (o SwComponents[I]) Values() ([]ISwComponent, error) {
	ret := make([]ISwComponent, len(o.values))

	for i, sc := range o.values {
		if err := sc.Validate(); err != nil {
			return nil, fmt.Errorf("failed at index %d: %w", i, err)
		}

		ret[i] = sc
	}

	return ret, nil
}

func (o *SwComponents[I]) Add(vals ...ISwComponent) error {
	toAdd, err := validateAndConvert[I](vals)
	if err != nil {
		return err
	}

	o.values = append(o.values, toAdd...)

	return nil
}

func (o *SwComponents[I]) Replace(vals []ISwComponent) error {
	newVals, err := validateAndConvert[I](vals)
	if err != nil {
		return err
	}

	o.values = newVals

	return nil
}

func (o SwComponents[I]) IsEmpty() bool {
	return len(o.values) == 0
}

func (o SwComponents[I]) MarshalCBOR() ([]byte, error) {
	return em.Marshal(o.values)
}

func (o *SwComponents[I]) UnmarshalCBOR(v []byte) error {
	return dm.Unmarshal(v, &o.values)
}

func (o SwComponents[I]) MarshalJSON() ([]byte, error) {
	return json.Marshal(o.values)
}

func (o *SwComponents[I]) UnmarshalJSON(v []byte) error {
	return json.Unmarshal(v, &o.values)
}

func validateAndConvert[I ISwComponent](vals []ISwComponent) ([]I, error) {
	ret := make([]I, len(vals))

	for i, sc := range vals {
		if err := sc.Validate(); err != nil {
			return nil, fmt.Errorf("failed at index %d: %w", i, err)
		}

		ta, ok := sc.(I)
		if !ok {
			return nil, fmt.Errorf("incorrect type at index %d; must be %s",
				i, reflect.TypeOf(*new(I)).Name())
		}
		ret[i] = ta

	}

	return ret, nil
}
