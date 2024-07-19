// Copyright 2021-2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package psatoken

import (
	"crypto"
	"crypto/rand"
	_ "crypto/sha256" // used hash algorithms need to be imported explicitly
	"errors"
	"fmt"
	"strings"

	cose "github.com/veraison/go-cose"
)

// DecodeAndValidateEvidenceFromCOSE returns an *Evidence containing COSE_Sign1
// message decoded from buf, and IClaims extracted from the message's payload.
// An error is returned if the decoding of either COSE_Sign1 message or the
// IClaims fails, or if the IClaims are not valid.
func DecodeAndValidateEvidenceFromCOSE(buf []byte) (*Evidence, error) {
	ev, err := DecodeEvidenceFromCOSE(buf)
	if err != nil {
		return nil, err
	}

	if err := ev.Claims.Validate(); err != nil {
		return nil, err
	}

	return ev, nil
}

// DecodeEvidenceFromCOSE returns an *Evidence containing COSE_Sign1 messaged
// decoded from buf, and IClaims extracted from the message's payload. An error
// is returned if the decoding of either COSE_Sign1 messarge or the IClaims
// fails.
func DecodeEvidenceFromCOSE(buf []byte) (*Evidence, error) {
	ev := &Evidence{}

	if err := ev.UnmarshalCOSE(buf); err != nil {
		return nil, err
	}

	return ev, nil
}

// Evidence is the wrapper around the PSA token, including the COSE envelope and
// the underlying claims
// nolint: golint
type Evidence struct {
	Claims  IClaims
	message *cose.Sign1Message
}

// SetClaims attaches the supplied claims to the Evidence instance.
// Only successfully validated claims are allowed to be set.
func (e *Evidence) SetClaims(claims IClaims) error {
	if err := claims.Validate(); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	e.Claims = claims

	return nil
}

// GetInstanceID returns the InstanceID claim that is to be used to locate the
// verification key or a nil pointer if no suitable InstanceID could be located.
// A call to this function on Evidence that has not been successfully verified
// is meaningless.
func (e *Evidence) GetInstanceID() *[]byte {
	instID, err := e.Claims.GetInstID()
	if err != nil {
		return nil
	}
	return &instID
}

// GetImplementationID returns the ImplementationID claim from the
// PSA token or a nil pointer if no suitable ImplementationID could
// be located.
func (e *Evidence) GetImplementationID() *[]byte {
	implID, err := e.Claims.GetImplID()
	if err != nil {
		return nil
	}
	return &implID
}

// UnmarshalCOSE extracts unvalidated claims wrapped in the supplied CWT.
// As per spec, the only acceptable security envelope is COSE_Sign1.
func (e *Evidence) UnmarshalCOSE(cwt []byte) error {
	var err error

	e.message = cose.NewSign1Message()

	if err = e.message.UnmarshalCBOR(cwt); err != nil {
		return fmt.Errorf("failed CBOR decoding for CWT: %w", err)
	}

	if e.Claims, err = DecodeClaimsFromCBOR(e.message.Payload); err != nil {
		return fmt.Errorf("failed CBOR decoding of PSA claims: %w", err)
	}

	return nil
}

// ValidateAndSign returns the Evidence wrapped in a CWT according to the supplied
// go-cose Signer.  (For now only COSE-Sign1 is supported.)
func (e *Evidence) ValidateAndSign(signer cose.Signer) ([]byte, error) {

	e.message = cose.NewSign1Message()

	var err error
	e.message.Payload, err = ValidateAndEncodeClaimsToCBOR(e.Claims)
	if err != nil {
		return nil, err
	}

	return e.doSign(signer)

}

// Sign returns the Evidence wrapped in a CWT according to the
// supplied go-cose Signer.  (For now only COSE-Sign1 is supported.) Unlike
// Sign, this does not validate the evidence before signing.
func (e *Evidence) Sign(signer cose.Signer) ([]byte, error) {

	e.message = cose.NewSign1Message()

	var err error
	e.message.Payload, err = EncodeClaimsToCBOR(e.Claims)
	if err != nil {
		return nil, err
	}

	return e.doSign(signer)
}

// Verify verifies any attached signature for the Evidence.
func (e *Evidence) Verify(pk crypto.PublicKey) error {
	if e.message == nil {
		return errors.New("no Sign1 message found")
	}
	protected := e.message.Headers.Protected

	algo, err := protected.Algorithm()
	if err != nil {
		return fmt.Errorf("unable to get verification algorithm: %w", err)
	}

	verifier, err := cose.NewVerifier(algo, pk)
	if err != nil {
		return fmt.Errorf("unable to instantiate verifier: %w", err)
	}

	err = e.message.Verify([]byte(""), verifier)
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

func (e *Evidence) doSign(signer cose.Signer) ([]byte, error) {
	alg := signer.Algorithm()

	if strings.Contains(alg.String(), "unknown algorithm value") {
		return nil, errors.New("signer has no algorithm")
	}

	e.message.Headers.Protected.SetAlgorithm(alg)

	err := e.message.Sign(rand.Reader, []byte(""), signer)
	if err != nil {
		return nil, err
	}

	wrap, err := e.message.MarshalCBOR()
	if err != nil {
		return nil, err
	}

	return wrap, nil
}
