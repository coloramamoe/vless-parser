.PHONY: run dry test lint check-links

run:
	go run . --check

dry:
	go run . --dry-run

test:
	go test ./...

lint:
	go vet ./...
	test -z "$$(gofmt -l .)"

check-links:
	go run . --check-links
