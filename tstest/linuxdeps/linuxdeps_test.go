package linuxdeps

import (
	"encoding/json"
	"os"
	"os/exec"
	"testing"
)

func TestDeps(t *testing.T) {
	cmd := exec.Command("go", "list", "-json", ".")
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm64")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	var res struct {
		Deps []string
	}
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatal(err)
	}
	for _, dep := range res.Deps {
		switch dep {
		case "gvisor.dev/gvisor/pkg/hostarch":
			t.Errorf("package %q is not allowed as a dependency on Linux (due to lack of support for >4K pages)", dep)
		}
	}
	t.Logf("got %d dependencies", len(res.Deps))
}
