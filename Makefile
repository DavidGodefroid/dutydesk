VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
RUNTIME ?= podman
CLAUDE_CODE_VERSION ?= 2.1.327
IMAGE ?= dutydesk-agent:$(CLAUDE_CODE_VERSION)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test lint fmt image

build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/dutydesk ./cmd/dutydesk
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/dutydesk-act ./cmd/dutydesk-act

test:
	go test -race -count=1 ./...

lint:
	go vet ./...
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed on:"; echo "$$out"; exit 1; fi

fmt:
	gofmt -w .

image:
	$(RUNTIME) build -t $(IMAGE) --build-arg CLAUDE_CODE_VERSION=$(CLAUDE_CODE_VERSION) -f agent/Containerfile agent
