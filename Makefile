.DEFAULT_GOAL := build
GO ?= go
PREFIX ?= $(HOME)/.local
.PHONY: build install compile test verify clean
build: install
install: compile
	python3 scripts/install-local.py --prefix "$(PREFIX)"
compile:
	mkdir -p build
	$(GO) build -trimpath -ldflags "-s -w -X main.version=$$(cat VERSION)" -o build/aegis ./cmd/aegis
test:
	$(GO) test -race ./...
verify: test
	$(GO) vet ./...
clean:
	rm -f build/aegis
