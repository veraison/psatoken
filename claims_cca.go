// CCA platform Claims
package psatoken

import (
	"encoding/json"
	"fmt"

	"github.com/veraison/eat"
)

type CcaPlatformClaims struct {
	Profile      *eat.Profile   `cbor:"265,keyasint" json:"cca-platform-profile"`
	Challenge    *eat.Nonce     `cbor:"10,keyasint" json:"cca-platform-challenge"`
	ImplID       *[]byte        `cbor:"2396,keyasint" json:"cca-platform-implementation-id"`
	InstID       *eat.UEID      `cbor:"256,keyasint" json:"cca-platform-instance-id"`
	Config       *[]byte        `cbor:"2401,keyasint" json:"cca-platform-config"`
	LifeCycle    *uint16        `cbor:"2395,keyasint" json:"cca-platform-lifecycle"`
	SwComponents *[]SwComponent `cbor:"2399,keyasint" json:"cca-platform-sw-components"`

	VSI       *string `cbor:"2400,keyasint,omitempty" json:"cca-platform-service-indicator,omitempty"`
	HashAlgID *string `cbor:"2402,keyasint" json:"cca-platform-hash-algo-id"`
}

func newCcaPlatformClaims() (IClaims, error) {
	var c CcaPlatformClaims

	if err := c.setProfile(); err != nil {
		return nil, err
	}

	return &c, nil
}

func (c *CcaPlatformClaims) setProfile() error {
	if c.Profile != nil {
		panic("profile already set")
	}

	p := eat.Profile{}

	if err := p.Set(CcaProfile); err != nil {
		return err
	}

	c.Profile = &p

	return nil
}

// Semantic validation
func (c CcaPlatformClaims) Validate() error {
	return validate(&c, CcaProfile)
}

// Codecs

func (c *CcaPlatformClaims) FromCBOR(buf []byte) error {
	err := dm.Unmarshal(buf, c)
	if err != nil {
		return fmt.Errorf("CBOR decoding of CCA platform claims failed: %w", err)
	}

	err = c.Validate()
	if err != nil {
		return fmt.Errorf("validation of CCA platform claims failed: %w", err)
	}

	return nil
}

func (c CcaPlatformClaims) ToCBOR() ([]byte, error) {
	err := c.Validate()
	if err != nil {
		return nil, fmt.Errorf("validation of CCA platform claims failed: %w", err)
	}

	buf, err := em.Marshal(&c)
	if err != nil {
		return nil, fmt.Errorf("CBOR encoding of CCA platform claims failed: %w", err)
	}

	return buf, nil
}

func (c *CcaPlatformClaims) FromJSON(buf []byte) error {
	err := json.Unmarshal(buf, c)
	if err != nil {
		return fmt.Errorf("JSON decoding of CCA platform claims failed: %w", err)
	}

	err = c.Validate()
	if err != nil {
		return fmt.Errorf("validation of CCA platform claims failed: %w", err)
	}

	return nil
}

func (c CcaPlatformClaims) ToJSON() ([]byte, error) {
	err := c.Validate()
	if err != nil {
		return nil, fmt.Errorf("validation of CCA platform claims failed: %w", err)
	}

	buf, err := json.Marshal(&c)
	if err != nil {
		return nil, fmt.Errorf("JSON encoding of CCA platform claims failed: %w", err)
	}

	return buf, nil
}

func (c *CcaPlatformClaims) SetImplID(v []byte) error {
	return setImplID(&c.ImplID, &v)
}

func (c *CcaPlatformClaims) SetNonce(v []byte) error {
	if err := isPSAHashType(v); err != nil {
		return err
	}

	n := eat.Nonce{}

	if err := n.Add(v); err != nil {
		return err
	}

	c.Challenge = &n

	return nil
}

func (c *CcaPlatformClaims) SetInstID(v []byte) error {
	if err := isValidInstID(v); err != nil {
		return err
	}

	ueid := eat.UEID(v)

	c.InstID = &ueid

	return nil
}

func (c *CcaPlatformClaims) SetVSI(v string) error {
	return setVSI(&c.VSI, &v)
}

func (c *CcaPlatformClaims) SetSecurityLifeCycle(v uint16) error {
	return setSecurityLifeCycle(&c.LifeCycle, &v, CcaProfile)
}

func (c *CcaPlatformClaims) SetBootSeed(v []byte) error {
	return fmt.Errorf("invalid SetBootSeed invoked on CCA platform claims")
}

func (c *CcaPlatformClaims) SetCertificationReference(v string) error {
	return fmt.Errorf("invalid SetCertificationReference invoked on CCA platform claims")
}

func (c CcaPlatformClaims) SetClientID(int32) error {
	return fmt.Errorf("invalid SetClientID invoked on CCA platform claims")
}

func (c *CcaPlatformClaims) SetSoftwareComponents(scs []SwComponent) error {
	if err := isValidSwComponents(scs); err != nil {
		return err
	}

	c.SwComponents = &scs

	return nil
}

func (c *CcaPlatformClaims) SetConfig(v []byte) error {

	if len(v) == 0 {
		return ErrMandatoryClaimMissing
	}
	c.Config = &v
	return nil
}

func (c *CcaPlatformClaims) SetHashAlgID(v string) error {

	if err := isValidHashAlgID(v); err != nil {
		return err
	}
	c.HashAlgID = &v
	return nil
}

// Getters return a validated value or an error
// After successful call to Validate(), getters of mandatory claims are assured
// to never fail.  Getters of optional claim may still fail with
// ErrOptionalClaimMissing in case the claim is not present.

func (c CcaPlatformClaims) GetProfile() (string, error) {
	if c.Profile == nil {
		return "", ErrMandatoryClaimMissing
	}

	return c.Profile.Get()
}

func (c CcaPlatformClaims) GetClientID() (int32, error) {
	return -1, fmt.Errorf("invalid GetClientID invoked on CCA platform claims")
}

func (c CcaPlatformClaims) GetSecurityLifeCycle() (uint16, error) {
	return getSecurityLifeCycle(c.LifeCycle, CcaProfile)
}

func (c CcaPlatformClaims) GetImplID() ([]byte, error) {
	return getImplID(c.ImplID)
}

func (c CcaPlatformClaims) GetBootSeed() ([]byte, error) {
	return nil, fmt.Errorf("invalid GetBootSeed invoked on CCA platform claims")
}

func (c CcaPlatformClaims) GetCertificationReference() (string, error) {
	return "", fmt.Errorf("invalid GetCertificationReference invoked on CCA platform claims")
}

func (c CcaPlatformClaims) GetSoftwareComponents() ([]SwComponent, error) {
	v := c.SwComponents

	if v == nil {
		return nil, ErrMandatoryClaimMissing
	}

	if err := isValidSwComponents(*v); err != nil {
		return nil, err
	}

	return *v, nil
}

func (c CcaPlatformClaims) GetNonce() ([]byte, error) {
	v := c.Challenge

	if v == nil {
		return nil, ErrMandatoryClaimMissing
	}

	l := v.Len()

	if l != 1 {
		return nil, fmt.Errorf("%w: got %d nonces, want 1", ErrWrongClaimSyntax, l)
	}

	n := v.GetI(0)
	if err := isValidNonce(n); err != nil {
		return nil, err
	}

	return n, nil
}

func (c CcaPlatformClaims) GetInstID() ([]byte, error) {
	v := c.InstID

	if v == nil {
		return nil, ErrMandatoryClaimMissing
	}

	if err := isValidInstID(*v); err != nil {
		return nil, err
	}

	return *v, nil
}

func (c CcaPlatformClaims) GetVSI() (string, error) {
	return getVSI(c.VSI)
}

func (c CcaPlatformClaims) GetConfig() ([]byte, error) {
	v := c.Config
	if v == nil {
		return nil, ErrMandatoryClaimMissing
	}
	return *v, nil
}

func (c CcaPlatformClaims) GetHashAlgID() (string, error) {
	v := c.HashAlgID

	if v == nil {
		return "", ErrMandatoryClaimMissing
	}
	if err := isValidHashAlgID(*v); err != nil {
		return "", err
	}
	return *v, nil
}
