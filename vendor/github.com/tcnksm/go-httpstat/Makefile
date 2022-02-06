PACKAGES = $(shell go list ./... | grep -v '/vendor/')

default: test

test-all: vet lint test

test: 
	go test -v -parallel=4 ${PACKAGES}

test-race:
	go test -v -race ${PACKAGES}

vet:
	go vet ${PACKAGES}

lint:
	@go get github.com/golang/lint/golint
	go list ./... | grep -v vendor | xargs -n1 golint 

cover:
	@go get golang.org/x/tools/cmd/cover		
	go test -coverprofile=cover.out
	go tool cover -html cover.out
	rm cover.out

.PHONY: test test-race vet lint cover	
