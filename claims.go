// Copyright 2021 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package psatoken

import (
	_ "crypto/sha256" // used hash algorithms need to be imported explicitly
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/eat"
)

const (
	// PSA_PROFILE_1 is the legacy profile defined in
	// draft-tschofenig-rats-psa-token-07 and earlier
	// nolint
	PSA_PROFILE_1 = "PSA_IOT_PROFILE_1"

	// PSA_PROFILE_2 is the new profile in
	// draft-tschofenig-rats-psa-token-08 and newer
	// which uses EAT claims where possible
	// nolint
	PSA_PROFILE_2 = "http://arm.com/psa/2.0.0"
)

func checkProfiles(profiles ...string) error {
	if len(profiles) == 0 {
		return errors.New("no profile supplied")
	}

	for _, profile := range profiles {
		if profile != PSA_PROFILE_1 && profile != PSA_PROFILE_2 {
			return fmt.Errorf("unknown profile: %s", profile)
		}
	}

	return nil
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

func partitionIDToString(pid int32) string {
	if pid <= 0 {
		return "nspe"
	}
	return "spe"
}

// Claims is the wrapper around PSA claims
// nolint: golint
type Claims struct {
	Profile           *eat.Profile  `cbor:"18,keyasint" json:"profile"`
	PartitionID       *int32        `cbor:"-75001,keyasint" json:"partition-id"`
	SecurityLifeCycle *uint16       `cbor:"-75002,keyasint" json:"security-life-cycle"`
	ImplID            *[]byte       `cbor:"-75003,keyasint" json:"implementation-id"`
	BootSeed          *[]byte       `cbor:"-75004,keyasint" json:"boot-seed"`
	HwVersion         *string       `cbor:"-75005,keyasint,omitempty" json:"hardware-version,omitempty"`
	SwComponents      []SwComponent `cbor:"-75006,keyasint,omitempty" json:"software-components,omitempty"`
	NoSwMeasurements  uint          `cbor:"-75007,keyasint,omitempty" json:"no-software-measurements,omitempty"`
	Nonce             *eat.Nonce    `cbor:"10,keyasint" json:"nonce"`
	InstID            *eat.UEID     `cbor:"11,keyasint" json:"instance-id"`
	VSI               string        `cbor:"-75010,keyasint,omitempty" json:"verification-service-indicator,omitempty"`

	// -07 and earlier
	LegacyProfile *string `cbor:"-75000,keyasint,omitempty" json:"legacy-profile,omitempty"`
	LegacyInstID  *[]byte `cbor:"-75009,keyasint,omitempty" json:"legacy-instance-id,omitempty"`
	LegacyNonce   *[]byte `cbor:"-75008,keyasint,omitempty" json:"legacy-nonce,omitempty"`

	// Decorations (only available to the JSON encoder)
	PartitionIDDesc       string `cbor:"-" json:"_partition-id-desc,omitempty"`
	SecurityLifeCycleDesc string `cbor:"-" json:"_security-lifecycle-desc,omitempty"`
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

func (p *Claims) instIDByProfile(profile string) *[]byte {
	switch profile {
	case PSA_PROFILE_1:
		return p.LegacyInstID
	case PSA_PROFILE_2:
		return (*[]byte)(p.InstID)
	default:
		return nil
	}
}

func (p *Claims) validateInstID(expectedProfile string) error {
	instID := p.instIDByProfile(expectedProfile)

	if instID == nil {
		return fmt.Errorf("missing mandatory instance-id")
	}

	l := len(*instID)

	if l != 33 {
		return fmt.Errorf(
			"invalid instance-id length %d (MUST be 33 bytes)",
			l,
		)
	}

	if (*instID)[0] != 0x01 {
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

func (p *Claims) validateNonce(expectedProfile string) error {
	switch expectedProfile {
	case PSA_PROFILE_1:
		if p.LegacyNonce == nil {
			return fmt.Errorf("missing mandatory nonce")
		}
		if err := isPSAHashType(*p.LegacyNonce); err != nil {
			return fmt.Errorf("invalid nonce: %w", err)
		}
		return nil
	case PSA_PROFILE_2:
		if p.Nonce == nil {
			return fmt.Errorf("missing mandatory nonce")
		}
		if p.Nonce.Len() != 1 {
			return errors.New("there must be exactly one nonce")
		}
		if err := isPSAHashType(p.Nonce.GetI(0)); err != nil {
			return fmt.Errorf("invalid nonce: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("unknown profile: %s", expectedProfile)
	}
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

func (p *Claims) decoratePartitionID() {
	// populate "_partition-id-desc"
	if p.PartitionID != nil {
		p.PartitionIDDesc = partitionIDToString(*p.PartitionID)
	}
}

// ToJSON returns the (indented) JSON representation of the Claims
func (p *Claims) ToJSON() (string, error) {
	/* TODO(tho)
	err := p.validate()
	if err != nil {
		return "", err
	}
	*/

	// add any available type enrichment
	p.decorate()

	buf, err := json.MarshalIndent(&p, "", "  ")
	if err != nil {
		return "", err
	}

	return string(buf), nil
}

// ToCBOR returns the CBOR representation of the Claims
func (p *Claims) ToCBOR() ([]byte, error) {
	/* No validation required here: in the emitter workflow, the PSA claims
	 * have been validated when they got attached to the Evidence via SetClaims */
	return cbor.Marshal(&p)
	// TODO(tho) configure the CBOR codec according to spec
}

// FromCBOR takes a bytes buffer containing a PSA token and, if successful,
// populates the receiver Claims object.
func (p *Claims) FromCBOR(buf []byte) error {
	err := cbor.Unmarshal(buf, p)
	if err != nil {
		return err
	}

	p.decorate()

	return nil
}

func (p *Claims) validate(profile string) error {
	err := p.validateProfile(profile)
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

	err = p.validateNonce(profile)
	if err != nil {
		return err
	}

	err = p.validateInstID(profile)
	if err != nil {
		return err
	}

	// There seem to be no reasons for an explicit validateVSI

	return nil
}

func (p *Claims) validateProfile(expectedProfile string) error {
	v := p.Profile

	if v != nil {
		profile, err := v.Get()
		if err != nil {
			return fmt.Errorf("error extracting profile: %w", err)
		}

		if profile != expectedProfile {
			return fmt.Errorf(
				"got profile '%s' want '%s'",
				profile, expectedProfile,
			)
		}
	} else {
		return fmt.Errorf("profile claim missing")
	}

	return nil
}

// SwComponent is the internal representation of a Software Component (section 3.4.1)
type SwComponent struct {
	MeasurementType  string  `cbor:"1,keyasint,omitempty" json:"measurement-type,omitempty"`
	MeasurementValue *[]byte `cbor:"2,keyasint" json:"measurement-value"`
	Version          string  `cbor:"4,keyasint,omitempty" json:"version,omitempty"`
	SignerID         *[]byte `cbor:"5,keyasint" json:"signer-id"`
	MeasurementDesc  string  `cbor:"6,keyasint,omitempty" json:"measurement-description,omitempty"`
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
