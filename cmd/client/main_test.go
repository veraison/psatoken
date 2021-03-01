package main

import (
	"fmt"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/psatoken"
)

func Test_clientConfig_loadSigner_file_not_found(t *testing.T) {
	f := "/nosuchfile"

	cfg := clientConfig{
		fileSys:        afero.NewMemMapFs(),
		signingKeyFile: f,
	}

	expected := fmt.Sprintf("reading from %s: open %s: file does not exist", f, f)

	_, actual := cfg.loadSigner()
	assert.EqualError(t, actual, expected)
}

func Test_clientConfig_loadSigner_parse_error(t *testing.T) {
	f := "/signer.json"

	cfg := clientConfig{
		fileSys:        afero.NewMemMapFs(),
		signingKeyFile: f,
	}

	err := afero.WriteFile(cfg.fileSys, cfg.signingKeyFile, []byte(`{}`), 0444)
	require.Nil(t, err)

	expected := fmt.Sprintf(
		"parsing key from %s: failed to unmarshal JWK: failed to unmarshal key from JSON headers: invalid key type from JSON ()",
		f,
	)

	_, actual := cfg.loadSigner()
	assert.EqualError(t, actual, expected)
}

func Test_clientConfig_loadSigner_key_extraction_error(t *testing.T) {
	f := "/signer.json"

	cfg := clientConfig{
		fileSys:        afero.NewMemMapFs(),
		signingKeyFile: f,
	}

	jwk := `{
	"kty": "EC",
	"crv": "bonkers",
	"x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
	"y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
	"d": "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
	"use": "enc",
	"kid": "1"
}`

	err := afero.WriteFile(cfg.fileSys, cfg.signingKeyFile, []byte(jwk), 0444)
	require.Nil(t, err)

	expected := fmt.Sprintf(
		"extracting raw key from set: failed to build public key: invalid curve algorithm bonkers",
	)

	_, actual := cfg.loadSigner()
	assert.EqualError(t, actual, expected)
}

func Test_clientConfig_loadSigner_unhandled_ec_curve(t *testing.T) {
	f := "/signer.json"

	cfg := clientConfig{
		fileSys:        afero.NewMemMapFs(),
		signingKeyFile: f,
	}

	// for the time being only P-256 is supported
	jwk := `{
	"kty": "EC",
	"crv": "P-384",
	"x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
	"y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
	"d": "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
	"use": "enc",
	"kid": "1"
}`

	err := afero.WriteFile(cfg.fileSys, cfg.signingKeyFile, []byte(jwk), 0444)
	require.Nil(t, err)

	expected := fmt.Sprintf("unhandled elliptic curve")

	_, actual := cfg.loadSigner()
	assert.EqualError(t, actual, expected)
}

func Test_clientConfig_loadSigner_not_a_private_key(t *testing.T) {
	f := "/signer.json"

	cfg := clientConfig{
		fileSys:        afero.NewMemMapFs(),
		signingKeyFile: f,
	}

	// for the time being only P-256 is supported
	jwk := `{
	"kty": "EC",
	"crv": "P-384",
	"x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
	"y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
	"use": "enc",
	"kid": "1"
}`

	err := afero.WriteFile(cfg.fileSys, cfg.signingKeyFile, []byte(jwk), 0444)
	require.Nil(t, err)

	expected := fmt.Sprintf("unknown private key type *ecdsa.PublicKey")

	_, actual := cfg.loadSigner()
	assert.EqualError(t, actual, expected)
}

func Test_clientConfig_loadSigner_happy_path(t *testing.T) {
	f := "/signer.json"

	cfg := clientConfig{
		fileSys:        afero.NewMemMapFs(),
		signingKeyFile: f,
	}

	jwk := `{
	"kty": "EC",
	"crv": "P-256",
	"x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
	"y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
	"d": "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
	"use": "enc",
	"kid": "1"
}`

	err := afero.WriteFile(cfg.fileSys, cfg.signingKeyFile, []byte(jwk), 0444)
	require.Nil(t, err)

	actual, err := cfg.loadSigner()
	assert.Nil(t, err)
	assert.NotNil(t, actual)
}

func Test_clientConfig_loadClaimsTemplate_file_not_found(t *testing.T) {
	f := "/nosuchfile"

	cfg := clientConfig{
		fileSys:    afero.NewMemMapFs(),
		claimsFile: f,
	}

	expected := fmt.Sprintf("reading from %s: open %s: file does not exist", f, f)

	_, actual := cfg.loadClaimsTemplate()
	assert.EqualError(t, actual, expected)
}

func Test_clientConfig_loadClaimsTemplate_parse_error(t *testing.T) {
	f := "/claims-template.json"

	cfg := clientConfig{
		fileSys:    afero.NewMemMapFs(),
		claimsFile: f,
	}

	err := afero.WriteFile(cfg.fileSys, cfg.claimsFile, []byte(`{`), 0444)
	require.Nil(t, err)

	expected := fmt.Sprintf("unmarshaling JSON template from %s: unexpected end of JSON input", f)

	_, actual := cfg.loadClaimsTemplate()
	assert.EqualError(t, actual, expected)
}

func Test_clientConfig_loadClaimsTemplate_happy_path(t *testing.T) {
	f := "/claims-template.json"

	cfg := clientConfig{
		fileSys:    afero.NewMemMapFs(),
		claimsFile: f,
	}

	expected := &psatoken.Claims{}

	err := afero.WriteFile(cfg.fileSys, cfg.claimsFile, []byte(`{}`), 0444)
	require.Nil(t, err)

	actual, err := cfg.loadClaimsTemplate()
	assert.Nil(t, err)
	assert.Equal(t, expected, actual)
}

func prepareFs(t *testing.T, noSigner, noClaims bool) *clientConfig {
	c := "/claims-template.json"
	s := "/signer.json"

	cfg := &clientConfig{
		fileSys:        afero.NewMemMapFs(),
		claimsFile:     c,
		signingKeyFile: s,
	}

	signerContent := `{
	"kty": "EC",
	"crv": "P-256",
	"x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
	"y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
	"d": "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
	"use": "enc",
	"kid": "1"
}`

	templateContent := `{
	"profile": "PSA_IOT_PROFILE_1",
	"partition-id": 2,
	"security-life-cycle": 12288,
	"implementation-id": "BwYFBAMCAQAPDg0MCwoJCBcWFRQTEhEQHx4dHBsaGRg=",
	"boot-seed": "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
	"hardware-version": "1234567890123",
	"software-components": [
		{
		"measurement-description": "TF-M_SHA256MemPreXIP",
		"measurement-type": "BL",
		"measurement-value": "BwYFBAMCAQAPDg0MCwoJCBcWFRQTEhEQHx4dHBsaGRY=",
		"signer-id": "BwYFBAMCAQAPDg0MCwoJCBcWFRQTEhEQHx4dHBsaGRg=",
		"version": "3.4.2"
		},
		{
		"measurement-type": "M1",
		"measurement-value": "BwYFBAMCAQAPDg0MCwoJCBcWFRQTEhEQHx4dHBsaGRc=",
		"signer-id": "BwYFBAMCAQAPDg0MCwoJCBcWFRQTEhEQHx4dHBsaGRg=",
		"version": "1.2.0"
		},
		{
		"measurement-type": "M2",
		"measurement-value": "BwYFBAMCAQAPDg0MCwoJCBcWFRQTEhEQHx4dHBsaGRg=",
		"signer-id": "BwYFBAMCAQAPDg0MCwoJCBcWFRQTEhEQHx4dHBsaGRg=",
		"version": "1.2.3"
		},
		{
		"measurement-type": "M3",
		"measurement-value": "BwYFBAMCAQAPDg0MCwoJCBcWFRQTEhEQHx4dHBsaGRk=",
		"signer-id": "BwYFBAMCAQAPDg0MCwoJCBcWFRQTEhEQHx4dHBsaGRg=",
		"version": "1.0.0"
		}
	],
	"instance-id": "AQcGBQQDAgEADw4NDAsKCQgXFhUUExIREB8eHRwbGhkY"
}`

	if !noClaims {
		err := afero.WriteFile(cfg.fileSys, cfg.claimsFile, []byte(templateContent), 0444)
		require.Nil(t, err)
	}

	if !noSigner {
		err := afero.WriteFile(cfg.fileSys, cfg.signingKeyFile, []byte(signerContent), 0444)
		require.Nil(t, err)
	}

	return cfg
}

func Test_clientCtx_BuildEvidence_no_matching_media_type(t *testing.T) {
	ctx := clientCtx{}

	accept := []string{
		"application/bonkers",
		"*/*",
		"not/sure",
		"",
	}

	_, _, err := ctx.BuildEvidence([]byte{}, accept)
	assert.EqualError(t, err, "no match on accepted media types")
}

func Test_clientCtx_BuildEvidence_nil(t *testing.T) {
	cfg := prepareFs(t, false, false)

	// do not load the signer

	c, err := cfg.loadClaimsTemplate()
	require.Nil(t, err)

	ctx := clientCtx{
		claims: c,
	}

	accept := []string{
		"application/psa-attestation-token",
	}

	_, _, err = ctx.BuildEvidence([]byte{}, accept)
	assert.EqualError(t, err, "token signing failed: nil signer")
}

func Test_clientCtx_BuildEvidence_happy_path(t *testing.T) {
	cfg := prepareFs(t, false, false)

	s, err := cfg.loadSigner()
	require.Nil(t, err)

	c, err := cfg.loadClaimsTemplate()
	require.Nil(t, err)

	ctx := clientCtx{
		signer: s,
		claims: c,
	}

	nonce := []byte{
		0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00,
		0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00,
	}

	accept := []string{
		"application/bonkers",
		"*/*",
		"application/psa-attestation-token",
	}

	expectedMediaType := "application/psa-attestation-token"

	actualEvidence, actualMediaType, err := ctx.BuildEvidence(nonce, accept)

	assert.Nil(t, err)
	assert.GreaterOrEqual(t, len(actualEvidence), 1)
	assert.Equal(t, expectedMediaType, actualMediaType)
}

func Test_clientConfig_runProtocol_no_URI(t *testing.T) {
	cfg := prepareFs(t, false, false)
	cfg.apiURL = ""

	actualAttestationResult, err := cfg.runProtocol()

	assert.EqualError(t, err, "challenge-response transaction failed: bad configuration: no API endpoint")
	assert.Nil(t, actualAttestationResult)
}

func Test_clientConfig_runProtocol_signer_not_found(t *testing.T) {
	cfg := prepareFs(t, true, false)

	actualAttestationResult, err := cfg.runProtocol()

	s := cfg.signingKeyFile

	expectedError := fmt.Sprintf(
		"loading signer from file: reading from %s: open %s: file does not exist",
		s, s,
	)

	assert.EqualError(t, err, expectedError)
	assert.Nil(t, actualAttestationResult)
}

func Test_clientConfig_runProtocol_claims_not_found(t *testing.T) {
	cfg := prepareFs(t, false, true)

	actualAttestationResult, err := cfg.runProtocol()

	c := cfg.claimsFile

	expectedError := fmt.Sprintf(
		"loading claims template from file: reading from %s: open %s: file does not exist",
		c, c,
	)

	assert.EqualError(t, err, expectedError)
	assert.Nil(t, actualAttestationResult)
}
