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

#TODO Reinstate Fuzz via Issue 24

.PHONY: docker
docker: ; docker build --pull --rm -f "cmd/client/Dockerfile" -t psatoken-client:latest "cmd/client" 

.PHONY: licenses
licenses: ; @./scripts/licenses.sh

.PHONY: help
help:
	@echo "Available targets:"
	@echo
	@echo "      test: run the package tests (default)"
	@echo "  coverage: run the package tests and show coverage profile"
	@echo "      lint: run golangci-lint using configuration from .golangci.yml"
	@echo "lint-extra: run golangci-lint using configuration from .golangci.yml"
	@echo "     clean: remove garbage"
	@echo "    docker: create a docker image of the psatoken-client CLI"
	@echo "  licenses: check licenses of dependent packages"
	@echo
