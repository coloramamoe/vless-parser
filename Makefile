.PHONY: run dry test lint check-links

run:
	go run ./src --check

dry:
	go run ./src --dry-run

test:
	go test ./...

lint:
	go vet ./...
	test -z "$$(gofmt -l .)"

check-links:
	go run ./src --check-links
