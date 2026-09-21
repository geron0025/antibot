VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: test
test:
	go test ./... -race -count=1

.PHONY: fuzz
fuzz:
	go test ./internal/tlsfp -run FuzzParseAgainstStdlib -fuzz FuzzParseAgainstStdlib -fuzztime 60s
	go test ./internal/h2fp -run FuzzSnifferDoesNotCrash -fuzz FuzzSnifferDoesNotCrash -fuzztime 60s
	go test ./internal/rules -run FuzzParse -fuzz FuzzParse -fuzztime 60s

# Two programs: the core, which serves traffic, and the admin UI, which
# runs beside it under a user of its own — or not at all.
.PHONY: build
build:
	go build -trimpath -ldflags "-s -w -X main.Version=$(VERSION)" -o antibot ./cmd/antibot
	go build -trimpath -ldflags "-s -w -X main.Version=$(VERSION)" -o antibot-admin ./cmd/antibot-admin

.PHONY: up
up:
	docker compose -f deploy/docker-compose.yml up --build -d

.PHONY: down
down:
	docker compose -f deploy/docker-compose.yml down

.PHONY: check
check: test
	gofmt -l . | tee /dev/stderr | test -z "$$(cat)"
	go vet ./...
