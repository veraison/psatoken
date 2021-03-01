package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"reflect"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/spf13/afero"
	"github.com/veraison/apiclient"
	cose "github.com/veraison/go-cose"
	"github.com/veraison/psatoken"
)

var (
	apiURL = flag.String(
		"url",
		"http://127.0.0.1:8888/challenge-response/v1/newSession",
		"URL of the challenge-reponse newSession API endpoint",
	)
	signingKeyFile = flag.String(
		"key",
		"pkey.pem",
		"file with the private key for signing the Evidence",
	)
	claimsFile = flag.String(
		"claims",
		"claims.json",
		"file with the PSA claims to sign in JSON format",
	)
)

// clientCtx satisfies the EvidenceBuilder interface
type clientCtx struct {
	signer *cose.Signer
	claims *psatoken.Claims
}

func (ctx clientCtx) BuildEvidence(nonce []byte, accept []string) ([]byte, string, error) {
	for _, ct := range accept {
		if ct == "application/psa-attestation-token" {
			token := psatoken.PSAToken{
				Claims: *ctx.claims,
			}

			token.Claims.Nonce = &nonce

			evidence, err := token.Sign(ctx.signer)
			if err != nil {
				return nil, "", fmt.Errorf("token signing failed: %w", err)
			}

			return evidence, ct, nil
		}
	}

	return nil, "", errors.New("no match on accepted media types")
}

type clientConfig struct {
	fileSys        afero.Fs
	claimsFile     string
	signingKeyFile string
	apiURL         string
}

func (cfg clientConfig) loadSigner() (*cose.Signer, error) {
	buf, err := afero.ReadFile(cfg.fileSys, cfg.signingKeyFile)
	if err != nil {
		return nil, fmt.Errorf("reading from %s: %w", cfg.signingKeyFile, err)
	}

	ks, err := jwk.Parse(bytes.NewReader(buf))
	if err != nil {
		return nil, fmt.Errorf("parsing key from %s: %w", cfg.signingKeyFile, err)
	}

	var key crypto.PrivateKey

	err = ks.Keys[0].Raw(&key)
	if err != nil {
		return nil, fmt.Errorf("extracting raw key from set: %w", err)
	}

	var crv elliptic.Curve
	var alg *cose.Algorithm

	switch v := key.(type) {
	case *ecdsa.PrivateKey:
		crv = v.Curve
		if crv == elliptic.P256() {
			alg = cose.ES256
			break
		}
		return nil, errors.New("unhandled elliptic curve")
	default:
		return nil, fmt.Errorf("unknown private key type %v", reflect.TypeOf(key))
	}

	return cose.NewSignerFromKey(alg, key)
}

func (cfg clientConfig) loadClaimsTemplate() (*psatoken.Claims, error) {
	buf, err := afero.ReadFile(cfg.fileSys, cfg.claimsFile)
	if err != nil {
		return nil, fmt.Errorf("reading from %s: %w", cfg.claimsFile, err)
	}

	c := &psatoken.Claims{}

	err = json.Unmarshal(buf, c)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling JSON template from %s: %w", cfg.claimsFile, err)
	}

	return c, nil
}

func (cfg clientConfig) runProtocol() ([]byte, error) {
	s, err := cfg.loadSigner()
	if err != nil {
		return nil, fmt.Errorf("loading signer from file: %v", err)
	}

	c, err := cfg.loadClaimsTemplate()
	if err != nil {
		return nil, fmt.Errorf("loading claims template from file: %v", err)
	}

	api := apiclient.ChallengeResponseConfig{
		NonceSz:         32,
		EvidenceBuilder: clientCtx{signer: s, claims: c},
		NewSessionURI:   cfg.apiURL,
	}

	attestationResult, err := api.Run()
	if err != nil {
		return nil, fmt.Errorf("challenge-response transaction failed: %v", err)
	}

	return attestationResult, nil
}

func main() {
	flag.Parse()

	cfg := clientConfig{
		fileSys:        afero.NewOsFs(),
		signingKeyFile: *signingKeyFile,
		claimsFile:     *claimsFile,
		apiURL:         *apiURL,
	}

	attestationResult, err := cfg.runProtocol()
	if err != nil {
		log.Fatalf("client failed: %v", err)
	}

	log.Printf("attestation result: %s", attestationResult)
}
