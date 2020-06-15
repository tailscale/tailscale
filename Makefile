usage:
	echo "See Makefile"

check: staticcheck

staticcheck:
	go run honnef.co/go/tools/cmd/staticcheck -- $$(go list ./... | grep -v tempfork)
