// Copyright 2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package psatoken

// ISwComponents defines an interface for a container of software components
// (implementing ISwComponent) interface. The existing generic implementation
// of this interface, SwComponents[I ISwComponent], should suffice for the vast
// majority of cases, and implementers of ISwComponent, typically should be
// able to just use that, and not have to implement ISwComponents as well.
type ISwComponents interface {
	// Validate returns an error if any of the contained ISwComponent's are
	// invalid.
	Validate() error
	// Values returns a []ISwComponents of the contained values. An error
	// may be returned if any of the contained valus are invalid.
	Values() ([]ISwComponent, error)
	// Add one or move ISwComponent's to the container, appending them to
	// the existing contents. An error may be returned if any of the values
	// being added are invalid.
	Add(vals ...ISwComponent) error
	// Replace the existing contents with the provided value. An error may
	// be returned if any of the new values are invalid.
	Replace(vals []ISwComponent) error
	// IsEmpty returns true if the container does not contain any values.
	IsEmpty() bool
}
