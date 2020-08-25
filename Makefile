usage:
	echo "See Makefile"

vet:
	go vet ./...

check: staticcheck vet

staticcheck:
	go run honnef.co/go/tools/cmd/staticcheck -- $$(go list ./... | grep -v tempfork)
