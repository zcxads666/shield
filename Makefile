.PHONY: build test run clean

build:
	go build -o bin/shield ./cmd/shield

test:
	go test -v ./...

run:
	go run ./cmd/shield -config config.yaml

clean:
	rm -rf bin/
