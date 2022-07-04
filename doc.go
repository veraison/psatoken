// Copyright 2021-2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

/*
Package psatoken provides an implementation of the following two PSA attestation
token profiles: PSA_IOT_PROFILE_1 and http://arm.com/psa/2.0.0

Creating a PSA Token

The creation of a PSA Token with profile http://arm.com/psa/2.0.0 comprises the
following steps (error checking omitted for brevity):

1. Create a claims-set with the desired profile:

	claims, _ := NewClaims(PsaProfile2)

2. Populate the mandatory part of the claims-set using the provided setter
   methods

	_ = claims.SetClientID(myClientID)
	_ = claims.SetSecurityLifeCycle(mySecurityLifeCycle)
	_ = claims.SetImplID(myImplID)
	_ = claims.SetInstID(myInstID)
	_ = claims.SetNonce(myNonce)
	_ = claims.SetSoftwareComponents(mySwComponents)

3. Populate any remaining optional claims:

	_ = claims.SetBootSeed(myBootSeed)
	_ = claims.SetCertificationReference(myCertificationReference)
	_ = claims.SetVSI(myVSI)

4. Add the claims to a psatoken.Evidence object (this will check the claims-set
   syntactic validity):

	evidence := psatoken.Evidence{}

	_ := evidence.SetClaims(claims)

4. Seal the evidence and serialize it to CBOR:

	// create a cose.Signer from private key
	signer, _ := cose.NewSignerFromKey(alg, key)

	cwt, _ := evidence.Sign(signer)

The output is a COSE Web Token that can be used as PDU in an attestation
protocol.

Consuming a PSA Token

Consuming a PSA Token comprises the following steps:

1. Decode the COSE Web Token:

	evidence := psatoken.Evidence{}

	_ := evidence.FromCOSE(cwt)

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
