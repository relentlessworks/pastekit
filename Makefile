BINARY = pastekit

.PHONY: build test vet run clean

build:
	CGO_ENABLED=0 go build -trimpath ./cmd/$(BINARY)

test:
	go test -race ./...

vet:
	go vet ./...

run:
	go run ./cmd/$(BINARY)

clean:
	rm -f $(BINARY) *.json
