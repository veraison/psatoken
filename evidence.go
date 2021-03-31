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

func (p *Evidence) SetClaims(claims Claims, profile string) error {
	if err := checkProfiles(profile); err != nil {
		return err
	}

	err := p.Claims.validate(profile)
	if err != nil {
		return err
	}

	p.Claims = claims

	return nil
}

// FromCOSE extracts the PSA claims wrapped in the supplied CWT. As per spec,
// the only acceptable security envelope is COSE-Sign1.
func (p *Evidence) FromCOSE(cwt []byte, supportedProfiles ...string) error {
	if err := checkProfiles(supportedProfiles...); err != nil {
		return fmt.Errorf(
			"PSA claims cannot be interpreted without specifying which PSA profile is supported: %w",
			err,
		)
	}

	if !cose.IsSign1Message(cwt) {
		return errors.New("not a COSE-Sign1 message")
	}

	p.message = cose.NewSign1Message()

	err := p.message.UnmarshalCBOR(cwt)
	if err != nil {
		return err
	}

	// To verify the CWT we need to locate the verification key
	// which is identified by the InstanceID claim inside the PSA
	// token.
	err = p.Claims.FromCBOR(p.message.Payload)
	if err != nil {
		return err
	}

	err = errors.New("no profile")
	for _, profile := range supportedProfiles {
		err = p.Claims.validate(profile)
		if err == nil {
			break
		}
	}

	if err != nil {
		return err
	}

	p.Claims.decorate()

	return nil
}

// Sign returns the Evidence wrapped in a CWT according to the supplied
// go-cose Signer.  (For now only COSE-Sign1 is supported.)
func (p *Evidence) Sign(signer *cose.Signer) ([]byte, error) {
	if signer == nil {
		return nil, errors.New("nil signer")
	}

	p.message = cose.NewSign1Message()

	var err error
	p.message.Payload, err = p.Claims.ToCBOR()
	if err != nil {
		return nil, err
	}

	alg := signer.GetAlg()
	if alg == nil {
		return nil, errors.New("signer has no algorithm")
	}

	p.message.Headers.Protected[1] = alg.Value

	err = p.message.Sign(rand.Reader, []byte(""), *signer)
	if err != nil {
		return nil, err
	}

	wrap, err := cose.Marshal(p.message)
	if err != nil {
		return nil, err
	}

	return wrap, nil
}

// Verify verifies any attached signature for the Evidence.
func (p *Evidence) Verify(pk crypto.PublicKey) error {
	if p.message == nil {
		return errors.New("token does not appear to be signed")
	}

	alg, err := cose.GetAlg(p.message.Headers)
	if err != nil {
		return err
	}

	verifier := cose.Verifier{
		Alg:       alg,
		PublicKey: pk,
	}

	err = p.message.Verify([]byte(""), verifier)
	if err != nil {
		return err
	}

	return nil
}
