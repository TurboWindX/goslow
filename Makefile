BINARY := goslow

# Static linux/amd64 binary (runs on any Kali, no interpreter/glibc worries).
build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o $(BINARY) .

# Local dev build for the host arch.
dev:
	go build -o $(BINARY) .

vet:
	go vet ./...

clean:
	rm -f $(BINARY)

.PHONY: build dev vet clean
