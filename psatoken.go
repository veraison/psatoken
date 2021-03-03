// Copyright 2021 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

// Package psatoken provides an implementation of draft-tschofenig-rats-psa-token-07
package psatoken

import (
	"crypto"
	"crypto/rand"
	_ "crypto/sha256" // used hash algorithms need to be imported explicitly
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/fxamacker/cbor/v2"
	cose "github.com/veraison/go-cose"
)

const (
	// PSA_PROFILE_1 is the profile defined in draft-tschofenig-rats-psa-token
	// which, at the moment, is the only one defined
	// nolint
	PSA_PROFILE_1 = "PSA_IOT_PROFILE_1"
)

// SwComponent is the internal representation of a Software Component (section 3.4.1)
type SwComponent struct {
	MeasurementType  string  `cbor:"1,keyasint,omitempty" json:"measurement-type,omitempty"`
	MeasurementValue *[]byte `cbor:"2,keyasint" json:"measurement-value"`
	Version          string  `cbor:"4,keyasint,omitempty" json:"version,omitempty"`
	SignerID         *[]byte `cbor:"5,keyasint" json:"signer-id"`
	MeasurementDesc  string  `cbor:"6,keyasint,omitempty" json:"measurement-description,omitempty"`
}

// Claims is the wrapper around PSA claims
// nolint: golint
type Claims struct {
	Profile           *string       `cbor:"-75000,keyasint" json:"profile"`
	PartitionID       *int32        `cbor:"-75001,keyasint" json:"partition-id"`
	SecurityLifeCycle *uint16       `cbor:"-75002,keyasint" json:"security-life-cycle"`
	ImplID            *[]byte       `cbor:"-75003,keyasint" json:"implementation-id"`
	BootSeed          *[]byte       `cbor:"-75004,keyasint" json:"boot-seed"`
	HwVersion         *string       `cbor:"-75005,keyasint,omitempty" json:"hardware-version,omitempty"`
	SwComponents      []SwComponent `cbor:"-75006,keyasint,omitempty" json:"software-components,omitempty"`
	NoSwMeasurements  uint          `cbor:"-75007,keyasint,omitempty" json:"no-software-measurements,omitempty"`
	Nonce             *[]byte       `cbor:"-75008,keyasint" json:"nonce"`
	InstID            *[]byte       `cbor:"-75009,keyasint" json:"instance-id"`
	VSI               string        `cbor:"-75010,keyasint,omitempty" json:"verification-service-indicator,omitempty"`

	// Decorations (only available to the JSON encoder)
	PartitionIDDesc       string `cbor:"-" json:"_partition-id-desc,omitempty"`
	SecurityLifeCycleDesc string `cbor:"-" json:"_security-lifecycle-desc,omitempty"`
}

// PSAToken is the wrapper around the PSA token, including the COSE envelope and
// the underlying claims
// nolint: golint
type PSAToken struct {
	Claims
	message *cose.Sign1Message
}

// nolint
const (
	// lifecycle state of the PSA RoT (see section 3.3.1)
	SECURITY_LIFECYCLE_UNKNOWN_MIN = 0x0000
	SECURITY_LIFECYCLE_UNKNOWN_MAX = 0x00ff

	SECURITY_LIFECYCLE_ASSEMBLY_AND_TEST_MIN = 0x1000
	SECURITY_LIFECYCLE_ASSEMBLY_AND_TEST_MAX = 0x10ff

	SECURITY_LIFECYCLE_PSA_ROT_PROVISIONING_MIN = 0x2000
	SECURITY_LIFECYCLE_PSA_ROT_PROVISIONING_MAX = 0x20ff

	SECURITY_LIFECYCLE_SECURED_MIN = 0x3000
	SECURITY_LIFECYCLE_SECURED_MAX = 0x30ff

	SECURITY_LIFECYCLE_NON_PSA_ROT_DEBUG_MIN = 0x4000
	SECURITY_LIFECYCLE_NON_PSA_ROT_DEBUG_MAX = 0x40ff

	SECURITY_LIFECYCLE_RECOVERABLE_PSA_ROT_DEBUG_MIN = 0x5000
	SECURITY_LIFECYCLE_RECOVERABLE_PSA_ROT_DEBUG_MAX = 0x50ff

	SECURITY_LIFECYCLE_DECOMMISSIONED_MIN = 0x6000
	SECURITY_LIFECYCLE_DECOMMISSIONED_MAX = 0x60ff
)

// clear spurious warning: "cyclomatic complexity 15 of function
// securityLifeCycleToString()"
// nolint: gocyclo
func securityLifeCycleToString(v uint16) string {
	if v >= SECURITY_LIFECYCLE_UNKNOWN_MIN &&
		v <= SECURITY_LIFECYCLE_UNKNOWN_MAX {
		return "unknown"
	}

	if v >= SECURITY_LIFECYCLE_ASSEMBLY_AND_TEST_MIN &&
		v <= SECURITY_LIFECYCLE_ASSEMBLY_AND_TEST_MAX {
		return "assembly-and-test"
	}

	if v >= SECURITY_LIFECYCLE_PSA_ROT_PROVISIONING_MIN &&
		v <= SECURITY_LIFECYCLE_PSA_ROT_PROVISIONING_MAX {
		return "psa-rot-provisioning"
	}

	if v >= SECURITY_LIFECYCLE_SECURED_MIN &&
		v <= SECURITY_LIFECYCLE_SECURED_MAX {
		return "secured"
	}

	if v >= SECURITY_LIFECYCLE_NON_PSA_ROT_DEBUG_MIN &&
		v <= SECURITY_LIFECYCLE_NON_PSA_ROT_DEBUG_MAX {
		return "non-psa-rot-debug"
	}

	if v >= SECURITY_LIFECYCLE_RECOVERABLE_PSA_ROT_DEBUG_MIN &&
		v <= SECURITY_LIFECYCLE_RECOVERABLE_PSA_ROT_DEBUG_MAX {
		return "recoverable-psa-rot-debug"
	}

	if v >= SECURITY_LIFECYCLE_DECOMMISSIONED_MIN &&
		v <= SECURITY_LIFECYCLE_DECOMMISSIONED_MAX {
		return "decommissioned"
	}

	return "invalid"
}

// FromCOSE unwraps a PSATokenClaims from the supplied CWT (For now only
// COSE-Sign1 wrapping is supported.)
func (p *PSAToken) FromCOSE(cwt []byte) error {
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
	err = p.FromCBOR(p.message.Payload)
	if err != nil {
		return err
	}

	return nil
}

// Sign returns the PSAToken wrapped in a CWT according to the supplied
// go-cose Signer.  (For now only COSE-Sign1 is supported.)
func (p *PSAToken) Sign(signer *cose.Signer) ([]byte, error) {
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

// Verify verifies any attached signature for the PSAToken.
func (p *PSAToken) Verify(pk crypto.PublicKey) error {
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

func (p *Claims) validate() error {
	err := p.validateProfile()
	if err != nil {
		return err
	}

	err = p.validatePartitionID()
	if err != nil {
		return err
	}

	err = p.validateSecurityLifeCycle()
	if err != nil {
		return err
	}

	err = p.validateImplID()
	if err != nil {
		return err
	}

	err = p.validateBootSeed()
	if err != nil {
		return err
	}

	err = p.validateHwVersion()
	if err != nil {
		return err
	}

	err = p.validateSwComponents()
	if err != nil {
		return err
	}

	err = p.validateNonce()
	if err != nil {
		return err
	}

	err = p.validateInstID()
	if err != nil {
		return err
	}

	// There seem to be no reasons for an explicit validateVSI

	return nil
}

func (p *Claims) validateProfile() error {
	v := p.Profile

	if v != nil && *v != PSA_PROFILE_1 {
		return fmt.Errorf(
			"unknown profile '%s' (MUST be '%s')",
			*v, PSA_PROFILE_1,
		)
	}

	return nil
}

func (p *Claims) validatePartitionID() error {
	if p.PartitionID == nil {
		return fmt.Errorf("missing mandatory partition-id")
	}

	// All values in the int range should be OK
	return nil
}

func (p *Claims) validateSecurityLifeCycle() error {
	v := p.SecurityLifeCycle

	if v == nil {
		return fmt.Errorf("missing mandatory security-life-cycle")
	}

	state := securityLifeCycleToString(*v)

	// For PSA, a remote verifier can only trust reports from the PSA RoT
	// when it is in SECURED or NON_PSA_ROT_DEBUG major states.
	if state == "secured" || state == "non-psa-rot-debug" {
		return nil
	}

	return fmt.Errorf(
		"unaccepted state: %s/%d (MUST be 'secured' or 'non-psa-rot-debug')",
		state, *v,
	)
}

func (p *Claims) validateImplID() error {
	if p.ImplID == nil {
		return fmt.Errorf("missing mandatory implementation-id")
	}

	l := len(*p.ImplID)

	if l != 32 {
		return fmt.Errorf(
			"invalid implementation-id length %d (MUST be 32 bytes)",
			l,
		)
	}

	return nil
}

func (p *Claims) validateInstID() error {
	if p.InstID == nil {
		return fmt.Errorf("missing mandatory instance-id")
	}

	l := len(*p.InstID)

	if l != 33 {
		return fmt.Errorf(
			"invalid instance-id length %d (MUST be 33 bytes)",
			l,
		)
	}

	if (*p.InstID)[0] != 0x01 {
		return fmt.Errorf(
			"invalid instance-id EUID type (MUST be RAND=0x01)",
		)
	}

	return nil
}

func (p *Claims) validateBootSeed() error {
	if p.BootSeed == nil {
		return fmt.Errorf("missing mandatory boot-seed")
	}

	l := len(*p.BootSeed)

	if l != 32 {
		return fmt.Errorf(
			"invalid boot-seed length %d (MUST be 32 bytes)",
			l,
		)
	}

	return nil
}

func (p *Claims) validateHwVersion() error {
	if p.HwVersion == nil {
		return nil
	}

	v := *p.HwVersion

	_, err := strconv.ParseUint(v, 10, 64)

	if err != nil || len(v) != 13 {
		return fmt.Errorf("invalid hardware-version format: MUST be GDSII")
	}

	return nil
}

func (p *Claims) validateNonce() error {
	if p.Nonce == nil {
		return fmt.Errorf("missing mandatory nonce")
	}

	if err := isPSAHashType(*p.Nonce); err != nil {
		return fmt.Errorf("invalid nonce %s", err.Error())
	}

	return nil
}

func (p *Claims) validateSwComponents() error {
	if p.NoSwMeasurements == 1 {
		if len(p.SwComponents) != 0 {
			return fmt.Errorf("no-software-measurements and software-components are mutually exclusive")
		}
		return nil
	}

	if len(p.SwComponents) == 0 {
		return fmt.Errorf("no software-components found")
	}

	for i, c := range p.SwComponents {
		err := c.validate(i)
		if err != nil {
			return err
		}
	}

	return nil
}

func (p SwComponent) validate(idx int) error {
	if p.MeasurementValue == nil {
		return fmt.Errorf(
			"invalid software-component[%d]: missing mandatory measurement-value",
			idx,
		)
	}

	if err := isPSAHashType(*p.MeasurementValue); err != nil {
		return fmt.Errorf(
			"invalid software-component[%d]: invalid measurement-value %s",
			idx, err.Error(),
		)
	}

	if p.SignerID == nil {
		return fmt.Errorf(
			"invalid software-component[%d]: missing mandatory signer-id",
			idx,
		)
	}

	if err := isPSAHashType(*p.SignerID); err != nil {
		return fmt.Errorf(
			"invalid software-component[%d]: invalid signer-id %s",
			idx, err.Error(),
		)
	}

	return nil
}

func isPSAHashType(b []byte) error {
	l := len(b)

	if l != 32 && l != 48 && l != 64 {
		return fmt.Errorf(
			"length %d (psa-hash-type MUST be 32, 48 or 64 bytes)",
			l,
		)
	}

	return nil

}

// decorate does type enrichment on the token, to add "hidden" attributes
// that will only be visible in the JSON (internal) encoding.
func (p *Claims) decorate() {
	p.decorateSecurityLifeCycle()
	p.decoratePartitionID()
}

func (p *Claims) decorateSecurityLifeCycle() {
	// populate "_security-lifecycle-desc"
	if p.SecurityLifeCycle != nil {
		p.SecurityLifeCycleDesc = securityLifeCycleToString(*p.SecurityLifeCycle)
	}
}

func partitionIDToString(pid int32) string {
	if pid <= 0 {
		return "nspe"
	}
	return "spe"
}

func (p *Claims) decoratePartitionID() {
	// populate "_partition-id-desc"
	if p.PartitionID != nil {
		p.PartitionIDDesc = partitionIDToString(*p.PartitionID)
	}
}

// ToJSON returns the (indented) JSON representation of the PSATokenClaims
func (p *Claims) ToJSON() (string, error) {
	err := p.validate()
	if err != nil {
		return "", err
	}

	// add any available type enrichment
	p.decorate()

	buf, err := json.MarshalIndent(&p, "", "  ")
	if err != nil {
		return "", err
	}

	return string(buf), nil
}

// ToCBOR returns the CBOR representation of the PSATokenClaims
func (p *Claims) ToCBOR() ([]byte, error) {
	err := p.validate()
	if err != nil {
		return nil, err
	}

	return cbor.Marshal(&p)
}

// FromCBOR takes a bytes buffer possibly containing a CBOR serialized PSA
// token and, if nil is returned, the target PSATokenClaims is populated.
func (p *Claims) FromCBOR(buf []byte) error {
	err := cbor.Unmarshal(buf, p)
	if err != nil {
		return err
	}

	err = p.validate()
	if err != nil {
		return err
	}

	p.decorate()

	return nil
}
