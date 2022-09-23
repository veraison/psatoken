#!/bin/bash
# Copyright 2022 Contributors to the Veraison project.
# SPDX-License-Identifier: Apache-2.0

set -eu
set -o pipefail

DIAG_FILES=
DIAG_FILES="${DIAG_FILES} P1ClaimsAll"
DIAG_FILES="${DIAG_FILES} P1ClaimsAllNoSwMeasurements"
DIAG_FILES="${DIAG_FILES} P1ClaimsMandatoryOnly"
DIAG_FILES="${DIAG_FILES} P1ClaimsMandatoryOnlyNoSwMeasurements"
DIAG_FILES="${DIAG_FILES} P1ClaimsMissingMandatoryNonce"
DIAG_FILES="${DIAG_FILES} P2ClaimsAll"
DIAG_FILES="${DIAG_FILES} P2ClaimsMandatoryOnly"
DIAG_FILES="${DIAG_FILES} P2ClaimsMissingMandatoryNonce"
DIAG_FILES="${DIAG_FILES} P2ClaimsInvalidMultiNonce"
DIAG_FILES="${DIAG_FILES} P1ClaimsTFM"
DIAG_FILES="${DIAG_FILES} P2ClaimsTFM"
DIAG_FILES="${DIAG_FILES} CcaPlatformClaimsAll"
DIAG_FILES="${DIAG_FILES} CcaPlatformClaimsInvalidMultiNonce"
DIAG_FILES="${DIAG_FILES} CcaPlatformClaimsMandatoryOnly"
DIAG_FILES="${DIAG_FILES} CcaPlatformClaimsMissingMandatoryNonce"

TV_DOT_GO=${TV_DOT_GO?must be set in the environment.}

printf "package psatoken\n\n" > ${TV_DOT_GO}

for t in ${DIAG_FILES}
do
	echo "// automatically generated from $t.diag" >> ${TV_DOT_GO}
	echo "var testEncoded${t} = "'`' >> ${TV_DOT_GO}
	cat ${t}.diag | diag2cbor.rb | xxd -p >> ${TV_DOT_GO}
	echo '`' >> ${TV_DOT_GO}
	gofmt -w ${TV_DOT_GO}
done
