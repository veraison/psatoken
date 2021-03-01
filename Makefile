.DEFAULT_GOAL := test

export GO111MODULE := on
export SHELL := /bin/bash

.PHONY: test
test: ; @go test -v ./...

.PHONY: coverage
coverage:
	@go test -v -cover -race -coverprofile=coverage.out ./... && \
                go tool cover -html=coverage.out
CLEANFILES += coverage.out

.PHONY: lint
lint: ; @golangci-lint run

.PHONY: lint-extra
lint-extra: ; @golangci-lint run --issues-exit-code=0 -E dupl -E gocritic -E gosimple -E lll -E prealloc

.PHONY: clean
clean: ; $(RM) -r $(CLEANFILES)

.PHONY: fuzz
fuzz: ; go-fuzz-build && go-fuzz

.PHONY: crashers
crashers:
	@env TEST_FUZZ_CRASHERS=1 go test -v -run TestPSAToken_fuzzer_crashers
CLEANFILES += psatoken-fuzz.zip
CLEANFILES += crashers
CLEANFILES += suppressions

.PHONY: help
help:
	@echo "Available targets:"
	@echo
	@echo "      test: run the package tests (default)"
	@echo "  coverage: run the package tests and show coverage profile"
	@echo "      lint: run golangci-lint using configuration from .golangci.yml"
	@echo "lint-extra: run golangci-lint using configuration from .golangci.yml"
	@echo "     clean: remove garbage"
	@echo "      fuzz: run go-fuzz using test vectors from corpus/"
	@echo "  crashers: go through the PDUs that managed to crash the fuzzer"
	@echo
