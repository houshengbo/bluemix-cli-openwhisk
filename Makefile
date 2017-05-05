SOURCEDIR=.

SOURCES := $(shell find $(SOURCEDIR) -name '*.go')
BINARY=wsk

VERSION=1.0.0

BUILD=`git rev-parse HEAD`

deps:
	@echo "Installing dependencies"
	go get -d -t ./...

LDFLAGS=-ldflags "-X main.CLI_BUILD_TIME=`date -u '+%Y-%m-%dT%H:%M:%S%:z'`"

updatedeps:
	@echo "Updating all dependencies"
	@go get -d -u -f -fix -t ./...

# Build the project
build: deps
	go build ${LDFLAGS} -o ${BINARY}

format:
	@echo "Formatting"
	go fmt ./...

lint: format
	@echo "Linting"
	golint .

install:
	go install

# Cleans our project: deletes binaries
clean:
	if [ -f ${BINARY} ] ; then rm ${BINARY}; fi

.PHONY: clean install