// Copyright 2021-2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package psatoken

import (
	_ "crypto/sha256" // used hash algorithms need to be imported explicitly
	"fmt"
	"regexp"
)

const (
	ImplIDLen = 32 // psa-implementation-id size (bytes .size 32)
	InstIDLen = 33 // psa-instance-id size (bytes .size 33)
)

const (
	SecurityLifecycleUnknownMin                = 0x0000
	SecurityLifecycleUnknownMax                = 0x00ff
	SecurityLifecycleAssemblyAndTestMin        = 0x1000
	SecurityLifecycleAssemblyAndTestMax        = 0x10ff
	SecurityLifecyclePsaRotProvisioningMin     = 0x2000
	SecurityLifecyclePsaRotProvisioningMax     = 0x20ff
	SecurityLifecycleSecuredMin                = 0x3000
	SecurityLifecycleSecuredMax                = 0x30ff
	SecurityLifecycleNonPsaRotDebugMin         = 0x4000
	SecurityLifecycleNonPsaRotDebugMax         = 0x40ff
	SecurityLifecycleRecoverablePsaRotDebugMin = 0x5000
	SecurityLifecycleRecoverablePsaRotDebugMax = 0x50ff
	SecurityLifecycleDecommissionedMin         = 0x6000
	SecurityLifecycleDecommissionedMax         = 0x60ff
)

type LifeCycleState uint16

const (
	StateUnknown LifeCycleState = iota
	StateAssemblyAndTest
	StatePSAROTProvisioning
	StateSecured
	StateNonPSAROTDebug
	StateRecoverablePSAROTDebug
	StateDecommissioned

	StateInvalid // must be last
)

func (o LifeCycleState) IsValid() bool {
	return o < StateInvalid
}

func (o LifeCycleState) String() string {
	switch o {
	case StateUnknown:
		return "unknown"
	case StateAssemblyAndTest:
		return "assembly-and-test"
	case StatePSAROTProvisioning:
		return "psa-rot-provisioning"
	case StateSecured:
		return "secured"
	case StateNonPSAROTDebug:
		return "non-psa-rot-debug"
	case StateRecoverablePSAROTDebug:
		return "recoverable-psa-rot-debug"
	case StateDecommissioned:
		return "decommissioned"
	default:
		return "invalid"
	}
}

func LifeCycleToState(v uint16) LifeCycleState {
	if v >= SecurityLifecycleUnknownMin &&
		v <= SecurityLifecycleUnknownMax {
		return StateUnknown
	}

	if v >= SecurityLifecycleAssemblyAndTestMin &&
		v <= SecurityLifecycleAssemblyAndTestMax {
		return StateAssemblyAndTest
	}

	if v >= SecurityLifecyclePsaRotProvisioningMin &&
		v <= SecurityLifecyclePsaRotProvisioningMax {
		return StatePSAROTProvisioning
	}

	if v >= SecurityLifecycleSecuredMin &&
		v <= SecurityLifecycleSecuredMax {
		return StateSecured
	}

	if v >= SecurityLifecycleNonPsaRotDebugMin &&
		v <= SecurityLifecycleNonPsaRotDebugMax {
		return StateNonPSAROTDebug
	}

	if v >= SecurityLifecycleRecoverablePsaRotDebugMin &&
		v <= SecurityLifecycleRecoverablePsaRotDebugMax {
		return StateRecoverablePSAROTDebug
	}

	if v >= SecurityLifecycleDecommissionedMin &&
		v <= SecurityLifecycleDecommissionedMax {
		return StateDecommissioned
	}

	return StateInvalid
}

func ValidateSecurityLifeCycle(v uint16) error {
	if !LifeCycleToState(v).IsValid() {
		return fmt.Errorf("%w: value %d is invalid", ErrWrongClaimSyntax, v)
	}

	return nil
}

var (
	CertificationReferenceP1RE = regexp.MustCompile(`^\d{13}$`)
	CertificationReferenceP2RE = regexp.MustCompile(`^\d{13}-\d{5}$`)
)

func ValidateImplID(v []byte) error {
	l := len(v)

	if l != ImplIDLen {
		return fmt.Errorf(
			"%w: invalid length %d (MUST be %d bytes)",
			ErrWrongClaimSyntax, l, ImplIDLen,
		)
	}

	return nil
}

func ValidatePSAHashType(b []byte) error {
	l := len(b)

	if l != 32 && l != 48 && l != 64 {
		return fmt.Errorf(
			"%w: length %d (hash MUST be 32, 48 or 64 bytes)",
			ErrWrongClaimSyntax, l,
		)
	}

	return nil
}

func ValidateInstID(v []byte) error {
	l := len(v)

	if l != InstIDLen {
		return fmt.Errorf(
			"%w: invalid length %d (MUST be %d bytes)",
			ErrWrongClaimSyntax, l, InstIDLen,
		)
	}

	if v[0] != 0x01 {
		return fmt.Errorf(
			"%w: invalid EUID type (MUST be RAND=0x01)",
			ErrWrongClaimSyntax,
		)
	}

	return nil
}

func ValidateVSI(v string) error {
	// https://github.com/thomas-fossati/draft-psa-token/issues/59
	if v == "" {
		return fmt.Errorf("%w: empty string", ErrWrongClaimSyntax)
	}

	return nil
}

func ValidateHashAlgID(v string) error {
	if v == "" {
		return fmt.Errorf("%w: empty string", ErrWrongClaimSyntax)
	}

	// It is recommended that IANA Hash Function Textual Names be used for setting HashAlgID
	switch v {
	case "md2", "md5", "sha-1", "sha-224", "sha-256", "sha-384", "sha-512", "shake128", "shake256":
		return nil
	}
	return fmt.Errorf("%w: wrong syntax", ErrWrongClaimSyntax)
}

func ValidateSwComponents(scs []SwComponent) error {
	if len(scs) == 0 {
		return fmt.Errorf("%w: there MUST be at least one entry", ErrWrongClaimSyntax)
	}

	for i, sc := range scs {
		if err := sc.Validate(); err != nil {
			return fmt.Errorf("failed at index %d: %w", i, err)
		}
	}

	return nil
}

func ValidateNonce(v []byte) error {
	return ValidatePSAHashType(v)
}
