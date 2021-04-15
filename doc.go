// Copyright 2021 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

/*
Package psatoken provides an implementation of draft-tschofenig-rats-psa-token-08

Creating a PSA Token

The creation of a PSA Token comprises the following steps:

1. Populating a psatoken.Claims object with the expected claims:

	claims := psatoken.Claims{
		Profile: psatoken.PSA_PROFILE_2,
		Nonce: nonce,
		// see psatoken.Claims{} for other claims
	}

2. Add the claims to a psatoken.Evidence object:

	evidence := psatoken.Evidence{}

	err := evidence.SetClaims(claims, psatoken.PSA_PROFILE_2)
	if err != nil {
		// handle error
	}

Note that the encoding profile needs to be specified and MUST match the
content of the Profile claim.

3. Seal the evidence and serialize it to CBOR:

	// create a cose.Signer from private key
	signer, err := cose.NewSignerFromKey(alg, key)
	if err != nil {
		// handle error
	}

	cwt, err := evidence.Sign(signer)
	if err != nil {
		// handle error
	}

The output is a COSE Web Token that can be used as PDU in an attestation
protocol.

Consuming a PSA Token

Consuming a PSA Token comprises the following steps:

1. Decode the COSE Web Token:

	evidence := psatoken.Evidence{}

	err := evidence.FromCOSE(cwt, psatoken.PSA_PROFILE_2, psatoken.PSA_PROFILE_1)
	if err != nil {
		// handle error
	}

Note that at least one supported profile MUST be supplied.

2. Verify using the public key associated with the InstanceID claim contained
in the token:

	// Lookup the verification public key (crypto.PublicKey) using the
	// InstanceID
	pk := myTrustAnchorStore.Lookup(evidence.GetInstanceID()

	err := evidence.Verify(pk)
	if err != nil {
		// handle error
	}

3. If cryptographic verification is successful, the PSA claims can be safely
processed, e.g.:

	myPolicy.VerifyAttestation(evidence.Claims)

*/
package psatoken
