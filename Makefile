.DEFAULT_GOAL := default

platform := $(shell uname)

GOFMT_FILES?=$$(find ./ -name '*.go' | grep -v vendor)

default: test test-cmd

test:
	@echo "executing tests..."
	cd ./test; go test -count 1 -v -race -timeout 20m ./...; cd -

test-cmd:
	docker-compose up -d && sleep 1 && go test -count 1 -v -race -timeout 1m ./cmd/...; docker-compose down

release:
	goreleaser release

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
