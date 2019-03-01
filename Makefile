.DEFAULT_GOAL := default

platform := $(shell uname)

GOFMT_FILES?=$$(find ./ -name '*.go' | grep -v vendor)

default: install-deps test

install-deps: install-goimports

install-goimports:
	@if [ ! -f ./goimports ]; then \
		go get golang.org/x/tools/cmd/goimports; \
	fi

test:
	@echo "executing tests..."
	@go test -count 1 -v -timeout 20m github.com/form3tech-oss/go-vault-client/pkg/vaultclient

vet:
	@echo "go vet ."
	@go vet $$(go list ./... | grep -v vendor/) ; if [ $$? -eq 1 ]; then \
		echo ""; \
		echo "Vet found suspicious constructs. Please check the reported constructs"; \
		echo "and fix them if necessary before submitting the code for review."; \
		exit 1; \
	fi

goimports:
	goimports -w $(GOFMT_FILES)

goimportscheck:
	@sh -c "'$(CURDIR)/scripts/goimportscheck.sh'"

errcheck:
	@sh -c "'$(CURDIR)/scripts/errcheck.sh'"



.PHONY: build test goimports errcheck
