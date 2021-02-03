// Copyright 2021 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package psatoken

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

// Fuzz is invoked by go-fuzz on the corpus
func Fuzz(data []byte) int {
	p := Claims{}

	err := p.FromCBOR(data)
	if err != nil {
		return 0
	}

	_, err = p.ToCBOR()
	if err != nil {
		panic(err)
	}

	return 1
}

// Invoke "make crashers" to run this test after go-fuzz completes, or even
// while go-fuzz is running if it's reporting any crasher already.
func TestClaims_fuzzer_crashers(t *testing.T) {
	if os.Getenv("TEST_FUZZ_CRASHERS") == "" {
		t.Skip("Skipping fuzz crashers")
	}

	warningString := `

===========================================================================
WARNING: there is a >0 chance that one or more of the following test cases
         will crash or hang.  *Do not run this in unattended environments.*
	 At the ready with CTRL-C / a debugger :-) Let's go!
===========================================================================

`
	t.Log(warningString)

	crashersDir := "./crashers/"

	files, err := ioutil.ReadDir(crashersDir)
	if err != nil || len(files) == 0 {
		t.Logf("%s directory not found (or empty)", crashersDir)
		t.Skip()
	}

	// Skip files with extension (.output and .quoted) and get the raw
	// binary data from the "unextended" file.  (This is the go-fuzz
	// filename convention.)
	re, err := regexp.Compile(`^([^.]+)$`)
	require.Nil(t, err, "compiling crashers regex")

	for _, f := range files {
		if f.IsDir() || !re.MatchString(f.Name()) {
			continue
		}

		tc, err := ioutil.ReadFile(filepath.Join(crashersDir, f.Name()))
		require.Nil(t, err, "loading binary data from %s", f.Name())

		t.Logf("running crasher %s", f.Name())

		p := Claims{}

		// Ignore error, the go-fuzz promise is the test case will hang
		// or crash and we can attach a debugger.
		_ = p.FromCBOR(tc)

		// If we get past this point then this was just a false
		// positive.
		t.Logf("crasher %s looks like a false positive", f.Name())
	}
}
