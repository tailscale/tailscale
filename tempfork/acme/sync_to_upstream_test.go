package acme

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	_ "github.com/tailscale/golang-x-crypto/acme" // so it's on disk for the test
)

// Verify that the files tempfork/acme/*.go (other than this test file) match the
// files in "github.com/tailscale/golang-x-crypto/acme" which is where we develop
// our fork of golang.org/x/crypto/acme and merge with upstream, but then we vendor
// just its acme package into tailscale.com/tempfork/acme.
//
// Development workflow:
//
//   - make a change in github.com/tailscale/golang-x-crypto/acme
//   - merge it (ideally with golang.org/x/crypto/acme too)
//   - rebase github.com/tailscale/golang-x-crypto/acme with upstream x/crypto/acme
//     as needed
//   - in the tailscale.com repo, run "go get github.com/tailscale/golang-x-crypto/acme@main"
//   - run go test ./tempfork/acme to watch it fail; the failure includes
//     a shell command you should run to copy the *.go files from tailscale/golang-x-crypto
//     to tailscale.com.
//   - watch tests pass. git add it all.
//   - send PR to tailscale.com
func TestSyncedToUpstream(t *testing.T) {
	const pkg = "github.com/tailscale/golang-x-crypto/acme"
	out, err := exec.Command("go", "list", "-f", "{{.Dir}}", pkg).Output()
	if err != nil {
		t.Fatalf("failed to find %s's location o disk: %v", pkg, err)
	}
	xDir := strings.TrimSpace(string(out))

	t.Logf("at %s", xDir)
	scanDir := func(dir string) map[string]string {
		m := map[string]string{} // filename => Go contents
		ents, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, de := range ents {
			name := de.Name()
			if name == "sync_to_upstream_test.go" {
				continue
			}
			if !strings.HasSuffix(name, ".go") {
				continue
			}
			b, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatal(err)
			}
			m[name] = strings.ReplaceAll(string(b), "\r", "")
		}

		return m
	}

	want := scanDir(xDir)
	got := scanDir(".")
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("files differ (-want +got):\n%s", diff)
		t.Errorf("to fix, run from module root:\n\ncp %s/*.go ./tempfork/acme && ./tool/go mod tidy\n", xDir)
	}
}
