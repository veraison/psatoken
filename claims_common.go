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
	// PsaProfile1 is the legacy profile defined in
	// draft-tschofenig-rats-psa-token-07 and earlier
	// nolint
	PsaProfile1 = "PSA_IOT_PROFILE_1"

	// PsaProfile2 is the new profile in
	// draft-tschofenig-rats-psa-token-08 and newer
	// which uses EAT claims where possible
	// nolint
	PsaProfile2 = "http://arm.com/psa/2.0.0"

	// CcaProfile is the new profile as defined in
	// RMM Monitor Specification, which uses EAT claims
	// where possible
	// nolint
	CcaProfile = "http://arm.com/CCA-SSD/1.0.0"
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

type PsaLifeCycleState uint16

const (
	PsaStateUnknown PsaLifeCycleState = iota
	PsaStateAssemblyAndTest
	PsaStatePsaRotProvisioning
	PsaStateSecured
	PsaStateNonPsaRotDebug
	PsaStateRecoverablePsaRotDebug
	PsaStateDecommissioned

	PsaStateInvalid // must be last
)

func (o PsaLifeCycleState) IsValid() bool {
	return o < PsaStateInvalid
}

func (o PsaLifeCycleState) String() string {
	switch o {
	case PsaStateUnknown:
		return "unknown"
	case PsaStateAssemblyAndTest:
		return "assembly-and-test"
	case PsaStatePsaRotProvisioning:
		return "psa-rot-provisioning"
	case PsaStateSecured:
		return "secured"
	case PsaStateNonPsaRotDebug:
		return "non-psa-rot-debug"
	case PsaStateRecoverablePsaRotDebug:
		return "recoverable-psa-rot-debug"
	case PsaStateDecommissioned:
		return "decommissioned"
	default:
		return "invalid"
	}
}

func PsaLifeCycleToState(v uint16) PsaLifeCycleState {
	if v >= SecurityLifecycleUnknownMin &&
		v <= SecurityLifecycleUnknownMax {
		return PsaStateUnknown
	}

	if v >= SecurityLifecycleAssemblyAndTestMin &&
		v <= SecurityLifecycleAssemblyAndTestMax {
		return PsaStateAssemblyAndTest
	}

	if v >= SecurityLifecyclePsaRotProvisioningMin &&
		v <= SecurityLifecyclePsaRotProvisioningMax {
		return PsaStatePsaRotProvisioning
	}

	if v >= SecurityLifecycleSecuredMin &&
		v <= SecurityLifecycleSecuredMax {
		return PsaStateSecured
	}

	if v >= SecurityLifecycleNonPsaRotDebugMin &&
		v <= SecurityLifecycleNonPsaRotDebugMax {
		return PsaStateNonPsaRotDebug
	}

	if v >= SecurityLifecycleRecoverablePsaRotDebugMin &&
		v <= SecurityLifecycleRecoverablePsaRotDebugMax {
		return PsaStateRecoverablePsaRotDebug
	}

	if v >= SecurityLifecycleDecommissionedMin &&
		v <= SecurityLifecycleDecommissionedMax {
		return PsaStateDecommissioned
	}

	return PsaStateInvalid
}

const (
	CcaPlatformLifecycleUnknownMin                     = 0x0000
	CcaPlatformLifecycleUnknownMax                     = 0x00ff
	CcaPlatformLifecycleAssemblyAndTestMin             = 0x1000
	CcaPlatformLifecycleAssemblyAndTestMax             = 0x10ff
	CcaPlatformLifecycleRotProvisioningMin             = 0x2000
	CcaPlatformLifecycleRotProvisioningMax             = 0x20ff
	CcaPlatformLifecycleSecuredMin                     = 0x3000
	CcaPlatformLifecycleSecuredMax                     = 0x30ff
	CcaPlatformLifecycleNonCcaPlatformDebugMin         = 0x4000
	CcaPlatformLifecycleNonCcaPlatformDebugMax         = 0x40ff
	CcaPlatformLifecycleRecoverableCcaPlatformDebugMin = 0x5000
	CcaPlatformLifecycleRecoverableCcaPlatformDebugMax = 0x50ff
	CcaPlatformLifecycleDecommissionedMin              = 0x6000
	CcaPlatformLifecycleDecommissionedMax              = 0x60ff
)

type CcaLifeCycleState uint16

const (
	CcaStateUnknown CcaLifeCycleState = iota
	CcaStateAssemblyAndTest
	CcaStateCcaRotProvisioning
	CcaStateSecured
	CcaStateNonCcaPlatformDebug
	CcaStateRecoverableCcaPlatformDebug
	CcaStateDecommissioned

	CcaStateInvalid // must be last
)

func (o CcaLifeCycleState) IsValid() bool {
	return o < CcaStateInvalid
}

func (o CcaLifeCycleState) String() string {
	switch o {
	case CcaStateUnknown:
		return "unknown"
	case CcaStateAssemblyAndTest:
		return "assembly-and-test"
	case CcaStateCcaRotProvisioning:
		return "cca-platform-rot-provisioning"
	case CcaStateSecured:
		return "secured"
	case CcaStateNonCcaPlatformDebug:
		return "non-cca-platform-rot-debug"
	case CcaStateRecoverableCcaPlatformDebug:
		return "recoverable-cca-platform-rot-debug"
	case CcaStateDecommissioned:
		return "decommissioned"
	default:
		return "invalid"
	}
}

func CcaLifeCycleToState(v uint16) CcaLifeCycleState {
	if v >= CcaPlatformLifecycleUnknownMin &&
		v <= CcaPlatformLifecycleUnknownMax {
		return CcaStateUnknown
	}

	if v >= CcaPlatformLifecycleAssemblyAndTestMin &&
		v <= CcaPlatformLifecycleAssemblyAndTestMax {
		return CcaStateAssemblyAndTest
	}

	if v >= CcaPlatformLifecycleRotProvisioningMin &&
		v <= CcaPlatformLifecycleRotProvisioningMax {
		return CcaStateCcaRotProvisioning
	}

	if v >= CcaPlatformLifecycleSecuredMin &&
		v <= CcaPlatformLifecycleSecuredMax {
		return CcaStateSecured
	}

	if v >= CcaPlatformLifecycleNonCcaPlatformDebugMin &&
		v <= CcaPlatformLifecycleNonCcaPlatformDebugMax {
		return CcaStateNonCcaPlatformDebug
	}

	if v >= CcaPlatformLifecycleRecoverableCcaPlatformDebugMin &&
		v <= CcaPlatformLifecycleRecoverableCcaPlatformDebugMax {
		return CcaStateRecoverableCcaPlatformDebug
	}

	if v >= CcaPlatformLifecycleDecommissionedMin &&
		v <= CcaPlatformLifecycleDecommissionedMax {
		return CcaStateDecommissioned
	}
	return CcaStateInvalid
}

func isValidSecurityLifeCycle(v uint16, profile string) error {
	var isValid bool

	switch profile {
	case PsaProfile1, PsaProfile2:
		isValid = PsaLifeCycleToState(v).IsValid()
	case CcaProfile:
		isValid = CcaLifeCycleToState(v).IsValid()
	}

	if !isValid {
		return fmt.Errorf("%w: value %d is invalid", ErrWrongClaimSyntax, v)
	}

	return nil
}

var (
	CertificationReferenceP1RE = regexp.MustCompile(`^[0-9]{13}$`)
	CertificationReferenceP2RE = regexp.MustCompile(`^[0-9]{13}-[0-9]{5}$`)
)

func isValidImplID(v []byte) error {
	l := len(v)

	if l != ImplIDLen {
		return fmt.Errorf(
			"%w: invalid length %d (MUST be %d bytes)",
			ErrWrongClaimSyntax, l, ImplIDLen,
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
				ErrWrongClaimSyntax, l,
			)
		}
	case PsaProfile1:
		if l != 32 {
			return fmt.Errorf(
				"%w: invalid length %d (MUST be 32 bytes)",
				ErrWrongClaimSyntax, l,
			)
		}
	}

	return nil
}

func isValidCertificationReference(v, profile string) error {
	switch profile {
	case PsaProfile1:
		if !CertificationReferenceP1RE.MatchString(v) &&
			!CertificationReferenceP2RE.MatchString(v) {
			return fmt.Errorf(
				"%w: MUST be in EAN-13 or EAN-13+5 format",
				ErrWrongClaimSyntax,
			)
		}
	case PsaProfile2:
		if !CertificationReferenceP2RE.MatchString(v) {
			return fmt.Errorf(
				"%w: MUST be in EAN-13+5 format",
				ErrWrongClaimSyntax,
			)
		}
	}

	return nil
}

func isPSAHashType(b []byte) error {
	l := len(b)

	if l != 32 && l != 48 && l != 64 {
		return fmt.Errorf(
			"%w: length %d (psa-hash-type MUST be 32, 48 or 64 bytes)",
			ErrWrongClaimSyntax, l,
		)
	}

	return nil
}

func isValidInstID(v []byte) error {
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

func isValidVSI(v string) error {
	// https://github.com/thomas-fossati/draft-psa-token/issues/59
	if v == "" {
		return fmt.Errorf("%w: empty string", ErrWrongClaimSyntax)
	}

	return nil
}

func isValidHashAlgID(v string) error {
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

func isValidSwComponents(scs []SwComponent) error {
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

func setSecurityLifeCycle(dst **uint16, src *uint16, profile string) error {
	if err := isValidSecurityLifeCycle(*src, profile); err != nil {
		return err
	}

	*dst = src

	return nil
}

func getSecurityLifeCycle(src *uint16, profile string) (uint16, error) {
	if src == nil {
		return 0, ErrMandatoryClaimMissing
	}

	if err := isValidSecurityLifeCycle(*src, profile); err != nil {
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

func setCertificationReference(dst **string, src *string, profile string) error {
	if err := isValidCertificationReference(*src, profile); err != nil {
		return err
	}

	*dst = src

	return nil
}

func getCertificationReference(src *string, profile string) (string, error) {
	if src == nil {
		return "", ErrOptionalClaimMissing
	}

	if err := isValidCertificationReference(*src, profile); err != nil {
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
