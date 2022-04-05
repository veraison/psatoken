// Copyright 2021 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package psatoken

import (
	_ "crypto/sha256" // used hash algorithms need to be imported explicitly
	"fmt"
	"strings"
)

const (
	ImplIDLen = 32 // psa-implementation-id size (bytes .size 32)
	InstIDLen = 33 // psa-instance-id size (bytes .size 33)
)

const (
	// PsaProfile1 is the legacy profile defined in
	// draft-tschofenig-rats-psa-token-07 and earlier
	// nolint
	PsaProfile1 = "PSA_IOT_PROFILE_1"

	// PsaProfile2 is the new profile in
	// draft-tschofenig-rats-psa-token-08 and newer
	// which uses EAT claims where possible
	// nolint
	PsaProfile2 = "http://arm.com/psa/2.0.0"
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

func securityLifeCycleToString(v uint16) string {
	if v >= SecurityLifecycleUnknownMin &&
		v <= SecurityLifecycleUnknownMax {
		return "unknown"
	}

	if v >= SecurityLifecycleAssemblyAndTestMin &&
		v <= SecurityLifecycleAssemblyAndTestMax {
		return "assembly-and-test"
	}

	if v >= SecurityLifecyclePsaRotProvisioningMin &&
		v <= SecurityLifecyclePsaRotProvisioningMax {
		return "psa-rot-provisioning"
	}

	if v >= SecurityLifecycleSecuredMin &&
		v <= SecurityLifecycleSecuredMax {
		return "secured"
	}

	if v >= SecurityLifecycleNonPsaRotDebugMin &&
		v <= SecurityLifecycleNonPsaRotDebugMax {
		return "non-psa-rot-debug"
	}

	if v >= SecurityLifecycleRecoverablePsaRotDebugMin &&
		v <= SecurityLifecycleRecoverablePsaRotDebugMax {
		return "recoverable-psa-rot-debug"
	}

	if v >= SecurityLifecycleDecommissionedMin &&
		v <= SecurityLifecycleDecommissionedMax {
		return "decommissioned"
	}

	return "invalid"
}

func isValidSecurityLifeCycle(v uint16) error {
	// Accept any security lifecycle in the state machine, including values that
	// can't produce trustable PSA evidence.
	if securityLifeCycleToString(v) == "invalid" {
		return fmt.Errorf("%w: value %d is invalid", ErrWrongSyntax, v)
	}

	return nil
}

func isValidImplID(v []byte) error {
	l := len(v)

	if l != ImplIDLen {
		return fmt.Errorf(
			"%w: invalid length %d (MUST be %d bytes)",
			ErrWrongSyntax, l, ImplIDLen,
		)
	}

	return nil
}

func isValidBootSeed(v []byte, profile string) error {
	l := len(v)

	switch profile {
	case PsaProfile2:
		if l < 8 || l > 32 {
			return fmt.Errorf(
				"%w: invalid length %d (MUST be between 8 and 32 bytes)",
				ErrWrongSyntax, l,
			)
		}
	case PsaProfile1:
		if l != 32 {
			return fmt.Errorf(
				"%w: invalid length %d (MUST be 32 bytes)",
				ErrWrongSyntax, l,
			)
		}
	}

	return nil
}

func isValidCertificationReference(v string) error {
	notDigit := func(c rune) bool { return c < '0' || c > '9' }

	if len(v) != 13 || strings.IndexFunc(v, notDigit) != -1 {
		return fmt.Errorf(
			"%w: MUST be in EAN-13 format",
			ErrWrongSyntax,
		)
	}

	return nil
}

func isPSAHashType(b []byte) error {
	l := len(b)

	if l != 32 && l != 48 && l != 64 {
		return fmt.Errorf(
			"%w: length %d (psa-hash-type MUST be 32, 48 or 64 bytes)",
			ErrWrongSyntax, l,
		)
	}

	return nil
}

func isValidInstID(v []byte) error {
	l := len(v)

	if l != InstIDLen {
		return fmt.Errorf(
			"%w: invalid length %d (MUST be %d bytes)",
			ErrWrongSyntax, l, InstIDLen,
		)
	}

	if v[0] != 0x01 {
		return fmt.Errorf(
			"%w: invalid EUID type (MUST be RAND=0x01)",
			ErrWrongSyntax,
		)
	}

	return nil
}

func isValidVSI(v string) error {
	// https://github.com/thomas-fossati/draft-psa-token/issues/59
	if v == "" {
		return fmt.Errorf("%w: empty string", ErrWrongSyntax)
	}

	return nil
}

func isValidSwComponents(scs []SwComponent) error {
	if len(scs) == 0 {
		return fmt.Errorf("%w: there MUST be at least one entry", ErrWrongSyntax)
	}

	for i, sc := range scs {
		if err := sc.Validate(); err != nil {
			return fmt.Errorf("failed at index %d: %w", i, err)
		}
	}

	return nil
}

func isValidNonce(v []byte) error {
	if err := isPSAHashType(v); err != nil {
		return err
	}

	return nil
}

func setClientID(dst **int32, src *int32) error {
	// any int32 value is acceptable
	*dst = src
	return nil
}

func getClientID(src *int32) (int32, error) {
	if src == nil {
		return 0, ErrMandatoryClaimMissing
	}

	return *src, nil
}

func setSecurityLifeCycle(dst **uint16, src *uint16) error {
	if err := isValidSecurityLifeCycle(*src); err != nil {
		return err
	}

	*dst = src

	return nil
}

func getSecurityLifeCycle(src *uint16) (uint16, error) {
	if src == nil {
		return 0, ErrMandatoryClaimMissing
	}

	if err := isValidSecurityLifeCycle(*src); err != nil {
		return 0, err
	}

	return *src, nil

}

func setImplID(dst **[]byte, src *[]byte) error {
	if err := isValidImplID(*src); err != nil {
		return err
	}

	*dst = src

	return nil
}

func getImplID(src *[]byte) ([]byte, error) {
	if src == nil {
		return nil, ErrMandatoryClaimMissing
	}

	if err := isValidImplID(*src); err != nil {
		return nil, err
	}

	return *src, nil

}

func setBootSeed(dst **[]byte, src *[]byte, profile string) error {
	if err := isValidBootSeed(*src, profile); err != nil {
		return err
	}

	*dst = src

	return nil
}

func getBootSeed(src *[]byte, profile string) ([]byte, error) {
	if src == nil {
		switch profile {
		case PsaProfile1:
			return nil, ErrMandatoryClaimMissing
		case PsaProfile2:
			return nil, ErrOptionalClaimMissing
		}
	}

	// boot seed is variable length in P2 and fixed length in P1
	if err := isValidBootSeed(*src, profile); err != nil {
		return nil, err
	}

	return *src, nil
}

func setCertificationReference(dst **string, src *string) error {
	if err := isValidCertificationReference(*src); err != nil {
		return err
	}

	*dst = src

	return nil
}

func getCertificationReference(src *string) (string, error) {
	if src == nil {
		return "", ErrOptionalClaimMissing
	}

	if err := isValidCertificationReference(*src); err != nil {
		return "", err
	}

	return *src, nil
}

func setVSI(dst **string, src *string) error {
	if err := isValidVSI(*src); err != nil {
		return err
	}

	*dst = src

	return nil
}

func getVSI(src *string) (string, error) {
	if src == nil {
		return "", ErrOptionalClaimMissing
	}

	if err := isValidVSI(*src); err != nil {
		return "", err
	}

	return *src, nil
}
