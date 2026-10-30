NAME := up2date
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
RELEASE_TARGETS := linux/amd64 linux/arm64

.PHONY: build release test clean

build:
	go build -ldflags="-X main.version=$(VERSION)" -o $(NAME) .

release:
	rm -rf dist && mkdir -p dist
	@for t in $(RELEASE_TARGETS); do \
		os=$${t%/*}; arch=$${t#*/}; \
		echo "building $${os}_$${arch}"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags="$(LDFLAGS)" -o dist/$(NAME)_$${os}_$${arch} . || exit 1; \
	done
	cd dist && shasum -a 256 $(NAME)_* > SHA256SUMS

test:
	test -z "$$(gofmt -l .)"
	go vet ./...
	go test ./...

clean:
	rm -rf dist $(NAME)

# A test environment with Dex and agents on several distributions: http://127.0.0.1:8484,
# admin@example.com / password. dev-reset also forgets the hosts and reports.
.PHONY: dev dev-down dev-reset
dev:
	docker compose -f dev/compose.yaml up --build -d

dev-down:
	docker compose -f dev/compose.yaml down

dev-reset:
	docker compose -f dev/compose.yaml down -v
