// Copyright 2021 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package psatoken

import (
	"crypto"
	"crypto/rand"
	_ "crypto/sha256" // used hash algorithms need to be imported explicitly
	"errors"
	"fmt"

	cose "github.com/veraison/go-cose"
)

// Evidence is the wrapper around the PSA token, including the COSE envelope and
// the underlying claims
// nolint: golint
type Evidence struct {
	Claims  Claims
	message *cose.Sign1Message
}

// SetClaims attaches the supplied claims to the Evidence instance. The claims
// are checked for consistency with the given profile.
func (e *Evidence) SetClaims(claims *Claims, profile string) error {
	if err := checkSupportedProfiles(profile); err != nil {
		return err
	}

	err := claims.validate(profile)
	if err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	e.Claims = *claims

	return nil
}

// GetInstanceID returns the InstanceID claim that is to be used to locate the
// verification key or a nil pointer if no suitable InstanceID could be located.
// A call to this function on Evidence that has not been successfully verified
// is meaningless.
func (e *Evidence) GetInstanceID() *[]byte {
	instID, err := e.Claims.GetInstanceID()
	if err != nil {
		return nil
	}
	return instID
}

// FromCOSE extracts the PSA claims wrapped in the supplied CWT. As per spec,
// the only acceptable security envelope is COSE-Sign1.
func (e *Evidence) FromCOSE(cwt []byte, supportedProfiles ...string) error {
	err := checkSupportedProfiles(supportedProfiles...)
	if err != nil {
		return err
	}

	if !cose.IsSign1Message(cwt) {
		return errors.New("the supplied CWT is not a COSE-Sign1 message")
	}

	e.message = cose.NewSign1Message()

	err = e.message.UnmarshalCBOR(cwt)
	if err != nil {
		return fmt.Errorf("failed CBOR decoding for CWT: %w", err)
	}

	err = e.Claims.FromCBOR(e.message.Payload)
	if err != nil {
		return fmt.Errorf("failed CBOR decoding of PSA claims: %w", err)
	}

	// We can assume that the prunedProfile array has at least one element:
	// the condition has been checked at the top of the function by the call
	// to checkSupportedProfiles
	for _, profile := range supportedProfiles {
		verr := e.Claims.validate(profile)
		if verr == nil {
			err = nil
			break
		}

		if err == nil {
			err = fmt.Errorf("%v", verr)
		} else {
			err = fmt.Errorf("%v + %v", err, verr)
		}
	}

	if err != nil {
		return fmt.Errorf("claims validation failed: %w", err)
	}

	e.Claims.decorate()

	return nil
}

// Sign returns the Evidence wrapped in a CWT according to the supplied
// go-cose Signer.  (For now only COSE-Sign1 is supported.)
func (e *Evidence) Sign(signer *cose.Signer) ([]byte, error) {
	if signer == nil {
		return nil, errors.New("nil signer")
	}

	e.message = cose.NewSign1Message()

	var err error
	e.message.Payload, err = e.Claims.ToCBOR()
	if err != nil {
		return nil, err
	}

	alg := signer.GetAlg()
	if alg == nil {
		return nil, errors.New("signer has no algorithm")
	}

	e.message.Headers.Protected[1] = alg.Value

	err = e.message.Sign(rand.Reader, []byte(""), *signer)
	if err != nil {
		return nil, err
	}

	wrap, err := cose.Marshal(e.message)
	if err != nil {
		return nil, err
	}

	return wrap, nil
}

// Verify verifies any attached signature for the Evidence.
func (e *Evidence) Verify(pk crypto.PublicKey) error {
	if e.message == nil {
		return errors.New("no Sign1 message found")
	}

	alg, err := cose.GetAlg(e.message.Headers)
	if err != nil {
		return fmt.Errorf("unable to get verification algorithm: %w", err)
	}

	verifier := cose.Verifier{
		Alg:       alg,
		PublicKey: pk,
	}

	err = e.message.Verify([]byte(""), verifier)
	if err != nil {
		return err
	}

	return nil
}
