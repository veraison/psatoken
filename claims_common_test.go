// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package psatoken

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_PsaLifeCycleState(t *testing.T) {
	type TestVector struct {
		Val  uint16
		Text string
	}

	validTestVectors := []TestVector{
		{0x0000, "unknown"},
		{0x00a7, "unknown"},
		{0x00ff, "unknown"},
		{0x1010, "assembly-and-test"},
		{0x2001, "psa-rot-provisioning"},
		{0x20ff, "psa-rot-provisioning"},
		{0x3000, "secured"},
		{0x3090, "secured"},
		{0x30ff, "secured"},
		{0x4020, "non-psa-rot-debug"},
		{0x5000, "recoverable-psa-rot-debug"},
		{0x50af, "recoverable-psa-rot-debug"},
		{0x6001, "decommissioned"},
		{0x60ff, "decommissioned"},
	}

	for _, tv := range validTestVectors {
		state := LifeCycleToState(tv.Val)

		assert.True(t, state.IsValid())
		assert.Equal(t, tv.Text, state.String())
	}

	invalidTestVectors := []TestVector{
		{0x1500, "doesn't matter"},
		{0x6100, "won't be used"},
		{0x8a47, "who cares?"},
		{0xffff, "pineapples"},
	}

	for _, tv := range invalidTestVectors {
		state := LifeCycleToState(tv.Val)

		assert.False(t, state.IsValid())
		assert.Equal(t, "invalid", state.String())
	}
}
