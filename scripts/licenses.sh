#!/bin/bash
# Copyright 2022 Contributors to the Veraison project.
# SPDX-License-Identifier: Apache-2.0

set -e

type go-licenses &> /dev/null || go get github.com/google/go-licenses

MODULES+=("github.com/veraison/psatoken")

for module in ${MODULES[@]}
do
  echo ">> retrieving licenses [ ${module} ]"
  go-licenses csv ${module}
done
