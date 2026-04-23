.PHONY: build test clean build-linux-amd64 build-linux-arm64

build:
	go build -o psst ./cmd/psst/

test:
	go test ./... -v

clean:
	rm -f psst

build-linux-amd64:
	GOOS=linux GOARCH=amd64 go build -o psst-linux-amd64 ./cmd/psst/

build-linux-arm64:
	GOOS=linux GOARCH=arm64 go build -o psst-linux-arm64 ./cmd/psst/
