.PHONY: fuzz
fuzz: ; go-fuzz-build && go-fuzz

.PHONY: crashers
crashers:
	@env TEST_FUZZ_CRASHERS=1 go test -v -run TestPSAToken_fuzzer_crashers
CLEANFILES += psatoken-fuzz.zip
CLEANFILES += crashers
CLEANFILES += suppressions

include ../../mk/pkg.mk
