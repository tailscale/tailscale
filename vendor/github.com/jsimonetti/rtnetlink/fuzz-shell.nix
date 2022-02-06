with import <nixpkgs> { };
pkgs.mkShell {
  name = "go-fuzz";
  buildInputs = [ go ];
  shellHook = ''
    function setup() {
      mkdir -p $GOPATH/src
      pushd $GOPATH/src
      go get github.com/dvyukov/go-fuzz/go-fuzz
      go get github.com/dvyukov/go-fuzz/go-fuzz-build 
      popd
    }
    function teardown() {
      chmod -R u+w $GOPATH
      rm -rf $GOPATH
    }
    echo "Setup up fuzzing environment"
    export GOPATH=$(mktemp -d /tmp/GOPATH.XXXXXX)
    trap teardown EXIT
    setup
    alias fuzzbuild="$GOPATH/bin/go-fuzz-build -tags gofuzz -o fuzz.zip"
    alias fuzzlink="$GOPATH/bin/go-fuzz -bin=./fuzz.zip -workdir=testdata -func FuzzLinkMessage"
    alias fuzzaddress="$GOPATH/bin/go-fuzz -bin=./fuzz.zip -workdir=testdata -func FuzzAddressMessage"
    alias fuzzroute="$GOPATH/bin/go-fuzz -bin=./fuzz.zip -workdir=testdata -func FuzzRouteMessage"
    alias fuzzneigh="$GOPATH/bin/go-fuzz -bin=./fuzz.zip -workdir=testdata -func FuzzNeighMessage"
    echo "Fuzz environment ready. There are 5 aliases available:"
    echo ""
    echo "fuzzbuild   - will build the fuzzing file"
    echo "fuzzlink    - will start fuzzing Link Messages"
    echo "fuzzaddress - will start fuzzing Address Messages"
    echo "fuzzroute   - will start fuzzing Route Messages"
    echo "fuzzneigh   - will start fuzzing Neigh Messages"
    echo ""
  '';
}
