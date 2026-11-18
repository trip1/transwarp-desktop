GO ?= $(HOME)/.local/bin/mise exec go@1.27.4 -- go
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
export GOTOOLCHAIN := local
export CGO_ENABLED := 0

.PHONY: build test dist clean
build:
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o transwarp .

test:
	$(GO) vet ./... && $(GO) test -race ./...

# static linux-amd64 / linux-arm64 tarballs + SHA256SUMS in dist/
dist:
	rm -rf dist && mkdir -p dist
	for a in amd64 arm64; do \
		d=dist/transwarp-$(VERSION)-linux-$$a; mkdir -p $$d; \
		GOOS=linux GOARCH=$$a $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $$d/transwarp . || exit 1; \
		cp README.md packaging/transwarp.service $$d/; \
		tar -C dist -czf $$d.tar.gz $$(basename $$d); rm -rf $$d; \
	done
	cd dist && sha256sum *.tar.gz > SHA256SUMS

clean:
	rm -rf dist transwarp
