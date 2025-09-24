.PHONY: all build test clean

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
BINARY_NAME=certmitm
BINARY_UNIX=$(BINARY_NAME)_unix

all: build

build:
	$(GOBUILD) -race -o $(BINARY_NAME) -v ./cmd/certmitm

test:
	@echo "Running tests..."
	@$(GOTEST) -v ./cmd/... ./internal/... ./pkg/...

clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_UNIX)

run:
	$(GOBUILD) -o $(BINARY_NAME) -v ./cmd/certmitm
	./$(BINARY_NAME)

deps:
	$(GOMOD) tidy

# Cross compilation
build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(BINARY_UNIX) -v ./cmd/certmitm

docker-build:
	docker build -t $(BINARY_NAME):latest .

docker-run:
	docker run --rm -it --net=host --privileged $(BINARY_NAME):latest
