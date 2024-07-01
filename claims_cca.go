// Copyright 2021-2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
// CCA platform Claims

package psatoken

import (
	"encoding/json"
	"fmt"

	"github.com/veraison/eat"
)

type ICCAClaims interface {
	IClaims

	GetConfig() ([]byte, error)
	GetHashAlgID() (string, error)

	SetConfig([]byte) error
	SetHashAlgID(string) error
}

func ValidateCCAClaims(c ICCAClaims) error {
	if err := ValidateClaims(c); err != nil {
		return err
	}

	if err := FilterError(c.GetConfig()); err != nil {
		return fmt.Errorf("validating platform config: %w", err)
	}

	if err := FilterError(c.GetHashAlgID()); err != nil {
		return fmt.Errorf("validating platform hash algo id: %w", err)
	}

	return nil
}

const CCAProfileName = "http://arm.com/CCA-SSD/1.0.0"

type CCAPlatformProfile struct{}

func (o CCAPlatformProfile) GetName() string {
	return CCAProfileName
}

func (o CCAPlatformProfile) GetClaims() IClaims {
	return newCCAPlatformClaims()
}

const (
	CCAPlatformLifecycleUnknownMin                     = 0x0000
	CCAPlatformLifecycleUnknownMax                     = 0x00ff
	CCAPlatformLifecycleAssemblyAndTestMin             = 0x1000
	CCAPlatformLifecycleAssemblyAndTestMax             = 0x10ff
	CCAPlatformLifecycleRotProvisioningMin             = 0x2000
	CCAPlatformLifecycleRotProvisioningMax             = 0x20ff
	CCAPlatformLifecycleSecuredMin                     = 0x3000
	CCAPlatformLifecycleSecuredMax                     = 0x30ff
	CCAPlatformLifecycleNonCCAPlatformDebugMin         = 0x4000
	CCAPlatformLifecycleNonCCAPlatformDebugMax         = 0x40ff
	CCAPlatformLifecycleRecoverableCCAPlatformDebugMin = 0x5000
	CCAPlatformLifecycleRecoverableCCAPlatformDebugMax = 0x50ff
	CCAPlatformLifecycleDecommissionedMin              = 0x6000
	CCAPlatformLifecycleDecommissionedMax              = 0x60ff
)

type CCALifeCycleState uint16

const (
	CCAStateUnknown CCALifeCycleState = iota
	CCAStateAssemblyAndTest
	CCAStateCCARotProvisioning
	CCAStateSecured
	CCAStateNonCCAPlatformDebug
	CCAStateRecoverableCCAPlatformDebug
	CCAStateDecommissioned

	CCAStateInvalid // must be last
)

func (o CCALifeCycleState) IsValid() bool {
	return o < CCAStateInvalid
}

func (o CCALifeCycleState) String() string {
	switch o {
	case CCAStateUnknown:
		return "unknown"
	case CCAStateAssemblyAndTest:
		return "assembly-and-test"
	case CCAStateCCARotProvisioning:
		return "cca-platform-rot-provisioning"
	case CCAStateSecured:
		return "secured"
	case CCAStateNonCCAPlatformDebug:
		return "non-cca-platform-rot-debug"
	case CCAStateRecoverableCCAPlatformDebug:
		return "recoverable-cca-platform-rot-debug"
	case CCAStateDecommissioned:
		return "decommissioned"
	default:
		return "invalid"
	}
}

func CCALifeCycleToState(v uint16) CCALifeCycleState {
	if v >= CCAPlatformLifecycleUnknownMin &&
		v <= CCAPlatformLifecycleUnknownMax {
		return CCAStateUnknown
	}

	if v >= CCAPlatformLifecycleAssemblyAndTestMin &&
		v <= CCAPlatformLifecycleAssemblyAndTestMax {
		return CCAStateAssemblyAndTest
	}

	if v >= CCAPlatformLifecycleRotProvisioningMin &&
		v <= CCAPlatformLifecycleRotProvisioningMax {
		return CCAStateCCARotProvisioning
	}

	if v >= CCAPlatformLifecycleSecuredMin &&
		v <= CCAPlatformLifecycleSecuredMax {
		return CCAStateSecured
	}

	if v >= CCAPlatformLifecycleNonCCAPlatformDebugMin &&
		v <= CCAPlatformLifecycleNonCCAPlatformDebugMax {
		return CCAStateNonCCAPlatformDebug
	}

	if v >= CCAPlatformLifecycleRecoverableCCAPlatformDebugMin &&
		v <= CCAPlatformLifecycleRecoverableCCAPlatformDebugMax {
		return CCAStateRecoverableCCAPlatformDebug
	}

	if v >= CCAPlatformLifecycleDecommissionedMin &&
		v <= CCAPlatformLifecycleDecommissionedMax {
		return CCAStateDecommissioned
	}
	return CCAStateInvalid
}

func ValidateCCASecurityLifeCycle(v uint16) error {
	if !CCALifeCycleToState(v).IsValid() {
		return fmt.Errorf("%w: value %d is invalid", ErrWrongSyntax, v)
	}

	return nil
}

type CCAPlatformClaims struct {
	Profile           *eat.Profile  `cbor:"265,keyasint" json:"cca-platform-profile"`
	Challenge         *eat.Nonce    `cbor:"10,keyasint" json:"cca-platform-challenge"`
	ImplID            *[]byte       `cbor:"2396,keyasint" json:"cca-platform-implementation-id"`
	InstID            *eat.UEID     `cbor:"256,keyasint" json:"cca-platform-instance-id"`
	Config            *[]byte       `cbor:"2401,keyasint" json:"cca-platform-config"`
	SecurityLifeCycle *uint16       `cbor:"2395,keyasint" json:"cca-platform-lifecycle"`
	SwComponents      ISwComponents `cbor:"2399,keyasint" json:"cca-platform-sw-components"`

	VSI       *string `cbor:"2400,keyasint,omitempty" json:"cca-platform-service-indicator,omitempty"`
	HashAlgID *string `cbor:"2402,keyasint" json:"cca-platform-hash-algo-id"`
}

func newCCAPlatformClaims() ICCAClaims {
	p := eat.Profile{}
	if err := p.Set(CCAProfileName); err != nil {
		// should never get here as using known good constant as input
		panic(err)
	}

	return &CCAPlatformClaims{
		Profile:      &p,
		SwComponents: &SwComponents[*SwComponent]{},
	}
}

// Semantic validation
func (c *CCAPlatformClaims) Validate() error {
	return ValidateCCAClaims(c)
}

// Codecs

func (c *CCAPlatformClaims) FromCBOR(buf []byte) error {
	err := c.FromUnvalidatedCBOR(buf)
	if err != nil {
		return err
	}

	err = c.Validate()
	if err != nil {
		return fmt.Errorf("validation of CCA platform claims failed: %w", err)
	}

	return nil
}

func (c *CCAPlatformClaims) FromUnvalidatedCBOR(buf []byte) error {
	c.Profile = nil // clear profile to make sure we taked it from buf

	err := dm.Unmarshal(buf, c)
	if err != nil {
		return fmt.Errorf("CBOR decoding of CCA platform claims failed: %w", err)
	}

	return nil
}

func (c *CCAPlatformClaims) ToCBOR() ([]byte, error) {
	err := c.Validate()
	if err != nil {
		return nil, fmt.Errorf("validation of CCA platform claims failed: %w", err)
	}

	return c.ToUnvalidatedCBOR()
}

func (c *CCAPlatformClaims) ToUnvalidatedCBOR() ([]byte, error) {
	var scs ISwComponents
	if c.SwComponents != nil && c.SwComponents.IsEmpty() {
		scs = c.SwComponents
		c.SwComponents = nil
	}

	buf, err := em.Marshal(&c)
	if scs != nil {
		c.SwComponents = scs
	}
	if err != nil {
		return nil, fmt.Errorf("CBOR encoding of CCA platform claims failed: %w", err)
	}

	return buf, nil
}

func (c *CCAPlatformClaims) FromJSON(buf []byte) error {
	err := c.FromUnvalidatedJSON(buf)
	if err != nil {
		return err
	}

	err = c.Validate()
	if err != nil {
		return fmt.Errorf("validation of CCA platform claims failed: %w", err)
	}

	return nil
}

func (c *CCAPlatformClaims) FromUnvalidatedJSON(buf []byte) error {
	c.Profile = nil // clear profile to make sure we taked it from buf

	err := json.Unmarshal(buf, c)
	if err != nil {
		return fmt.Errorf("JSON decoding of CCA platform claims failed: %w", err)
	}

	return nil
}

func (c *CCAPlatformClaims) ToJSON() ([]byte, error) {
	err := c.Validate()
	if err != nil {
		return nil, fmt.Errorf("validation of CCA platform claims failed: %w", err)
	}

	return c.ToUnvalidatedJSON()
}

func (c *CCAPlatformClaims) ToUnvalidatedJSON() ([]byte, error) {
	var scs ISwComponents
	if c.SwComponents != nil && c.SwComponents.IsEmpty() {
		scs = c.SwComponents
		c.SwComponents = nil
	}

	buf, err := json.Marshal(&c)
	if scs != nil {
		c.SwComponents = scs
	}
	if err != nil {
		return nil, fmt.Errorf("JSON encoding of CCA platform claims failed: %w", err)
	}

	return buf, nil
}

func (c *CCAPlatformClaims) SetImplID(v []byte) error {
	if err := ValidateImplID(v); err != nil {
		return err
	}

	c.ImplID = &v

	return nil
}

func (c *CCAPlatformClaims) SetNonce(v []byte) error {
	if err := ValidatePSAHashType(v); err != nil {
		return err
	}

	n := eat.Nonce{}

	if err := n.Add(v); err != nil {
		return err
	}

	c.Challenge = &n

	return nil
}

func (c *CCAPlatformClaims) SetInstID(v []byte) error {
	if err := ValidateInstID(v); err != nil {
		return err
	}

	ueid := eat.UEID(v)

	c.InstID = &ueid

	return nil
}

func (c *CCAPlatformClaims) SetVSI(v string) error {
	if err := ValidateVSI(v); err != nil {
		return err
	}

	c.VSI = &v

	return nil
}

func (c *CCAPlatformClaims) SetSecurityLifeCycle(v uint16) error {
	if err := ValidateCCASecurityLifeCycle(v); err != nil {
		return err
	}

	c.SecurityLifeCycle = &v

	return nil
}

func (c *CCAPlatformClaims) SetBootSeed(v []byte) error {
	return fmt.Errorf("%w: boot seed", ErrClaimNotInProfile)
}

func (c *CCAPlatformClaims) SetCertificationReference(v string) error {
	return fmt.Errorf("%w: certification reference", ErrClaimNotInProfile)
}

func (c *CCAPlatformClaims) SetClientID(int32) error {
	return fmt.Errorf("%w: client id", ErrClaimNotInProfile)
}

func (c *CCAPlatformClaims) SetSoftwareComponents(scs []ISwComponent) error {
	if c.SwComponents == nil {
		c.SwComponents = &SwComponents[*SwComponent]{}
	}

	return c.SwComponents.Replace(scs)
}

func (c *CCAPlatformClaims) SetConfig(v []byte) error {
	if len(v) == 0 {
		return ErrMandatoryClaimMissing
	}

	c.Config = &v

	return nil
}

func (c *CCAPlatformClaims) SetHashAlgID(v string) error {
	if err := ValidateHashAlgID(v); err != nil {
		return err
	}

	c.HashAlgID = &v

	return nil
}

// Getters return a validated value or an error
// After successful call to Validate(), getters of mandatory claims are assured
// to never fail.  Getters of optional claim may still fail with
// ErrOptionalClaimMissing in case the claim is not present.
func (c *CCAPlatformClaims) GetProfile() (string, error) {
	if c.Profile == nil {
		return "", ErrMandatoryClaimMissing
	}

	profileString, err := c.Profile.Get()
	if err != nil {
		return "", err
	}

	if profileString != CCAProfileName {
		return "", fmt.Errorf("%w: expecting %q, got %q",
			ErrWrongProfile, CCAProfileName, profileString)
	}

	return c.Profile.Get()
}

func (c *CCAPlatformClaims) GetClientID() (int32, error) {
	return -1, fmt.Errorf("%w: client id", ErrClaimNotInProfile)
}

func (c *CCAPlatformClaims) GetSecurityLifeCycle() (uint16, error) {
	if c.SecurityLifeCycle == nil {
		return 0, ErrMandatoryClaimMissing
	}

	if err := ValidateSecurityLifeCycle(*c.SecurityLifeCycle); err != nil {
		return 0, err
	}

	return *c.SecurityLifeCycle, nil
}

func (c *CCAPlatformClaims) GetImplID() ([]byte, error) {
	if c.ImplID == nil {
		return nil, ErrMandatoryClaimMissing
	}

	if err := ValidateImplID(*c.ImplID); err != nil {
		return nil, err
	}

	return *c.ImplID, nil
}

func (c *CCAPlatformClaims) GetBootSeed() ([]byte, error) {
	return nil, fmt.Errorf("%w: boot seed", ErrClaimNotInProfile)
}

func (c *CCAPlatformClaims) GetCertificationReference() (string, error) {
	return "", fmt.Errorf("%w: certification reference", ErrClaimNotInProfile)
}

func (c *CCAPlatformClaims) GetSoftwareComponents() ([]ISwComponent, error) {
	if c.SwComponents == nil || c.SwComponents.IsEmpty() {
		return nil, fmt.Errorf("%w (MUST have at least one sw component)",
			ErrMandatoryClaimMissing)
	}

	return c.SwComponents.Values()
}

func (c *CCAPlatformClaims) GetNonce() ([]byte, error) {
	v := c.Challenge

	if v == nil {
		return nil, ErrMandatoryClaimMissing
	}

	l := v.Len()

	if l != 1 {
		return nil, fmt.Errorf("%w: got %d nonces, want 1", ErrWrongSyntax, l)
	}

	n := v.GetI(0)
	if err := ValidateNonce(n); err != nil {
		return nil, err
	}

	return n, nil
}

func (c *CCAPlatformClaims) GetInstID() ([]byte, error) {
	v := c.InstID

	if v == nil {
		return nil, ErrMandatoryClaimMissing
	}

	if err := ValidateInstID(*v); err != nil {
		return nil, err
	}

	return *v, nil
}

func (c *CCAPlatformClaims) GetVSI() (string, error) {
	if c.VSI == nil {
		return "", ErrOptionalClaimMissing
	}

	if err := ValidateVSI(*c.VSI); err != nil {
		return "", err
	}

	return *c.VSI, nil
}

func (c *CCAPlatformClaims) GetConfig() ([]byte, error) {
	v := c.Config
	if v == nil {
		return nil, ErrMandatoryClaimMissing
	}
	return *v, nil
}

func (c *CCAPlatformClaims) GetHashAlgID() (string, error) {
	v := c.HashAlgID

	if v == nil {
		return "", ErrMandatoryClaimMissing
	}
	if err := ValidateHashAlgID(*v); err != nil {
		return "", err
	}
	return *v, nil
}

func init() {
	if err := RegisterProfile(CCAPlatformProfile{}); err != nil {
		panic(err)
	}
}
