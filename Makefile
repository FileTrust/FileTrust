# Modified by FileTrust for a standalone source distribution.
# Derived from the Cosmos EVM build; Apache-2.0, see LICENSE and NOTICE.

GO ?= go
VERSION ?= development
COMMIT := $(shell git rev-parse HEAD 2>/dev/null || printf unknown)
BUILDDIR ?= $(CURDIR)/build
BUILD_TAGS ?= netgo
LDFLAGS := -s -w \
  -X github.com/cosmos/cosmos-sdk/version.Name=filetrust \
  -X github.com/cosmos/cosmos-sdk/version.AppName=filetrustd \
  -X github.com/cosmos/cosmos-sdk/version.Version=$(VERSION) \
  -X github.com/cosmos/cosmos-sdk/version.Commit=$(COMMIT)

.PHONY: build contracts check
build:
	mkdir -p "$(BUILDDIR)"
	cd evmd && CGO_ENABLED=1 $(GO) build -mod=readonly -buildvcs=false -trimpath -tags '$(BUILD_TAGS)' -ldflags '$(LDFLAGS)' -o "$(BUILDDIR)/filetrustd" ./cmd/evmd

contracts:
	cd filetrust/evm && npm ci --ignore-scripts && npm run compile && npm run check:sizes

check:
	python3 scripts/check_publication.py
