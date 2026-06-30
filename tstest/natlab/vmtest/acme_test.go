// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest_test

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/creachadair/mds/shell"
	"tailscale.com/tstest/natlab/vmtest"
	"tailscale.com/tstest/natlab/vnet"
)

func TestACMECertServeHTTPS(t *testing.T) {
	env := vmtest.New(t, vmtest.FakeACME())
	issuer := ubuntuHard(env, "issuer")
	client := ubuntuHard(env, "client")
	env.Start()

	st := env.Status(issuer)
	if len(st.CertDomains) == 0 {
		t.Fatalf("issuer has no CertDomains in status")
	}
	domain := st.CertDomains[0]

	out, err := env.SSHExec(issuer, certAndWatchHealthCommand(domain))
	if err != nil {
		t.Fatalf("tailscale cert: %v\n%s", err, out)
	}

	out, err = env.SSHExec(issuer, "tailscale serve --bg --https=443 text:natlab-acme-ok")
	if err != nil {
		t.Fatalf("tailscale serve: %v\n%s", err, out)
	}

	rootB64 := base64.StdEncoding.EncodeToString(env.FakeACMERootPEM())
	out, err = env.SSHExec(client, "printf %s "+shell.Quote(rootB64)+" | base64 -d >/tmp/fake-acme-root.pem")
	if err != nil {
		t.Fatalf("install fake ACME root: %v\n%s", err, out)
	}
	out, err = env.SSHExec(client, "curl --fail --silent --show-error --cacert /tmp/fake-acme-root.pem https://"+shell.Quote(domain)+"/")
	if err != nil {
		t.Fatalf("curl served HTTPS page: %v\n%s", err, out)
	}
	if strings.TrimSpace(out) != "natlab-acme-ok" {
		t.Fatalf("curl body = %q, want %q", out, "natlab-acme-ok")
	}
}

func ubuntuHard(env *vmtest.Env, name string) *vmtest.Node {
	n := env.NumNodes()
	return env.AddNode(name,
		env.AddNetwork(
			fmt.Sprintf("2.%d.%d.%d", n, n, n),
			fmt.Sprintf("10.0.%d.1/24", n), vnet.HardNAT),
		vmtest.OS(vmtest.Ubuntu2404))
}

func certAndWatchHealthCommand(domain string) string {
	qdomain := shell.Quote(domain)
	return fmt.Sprintf(`
set -eu
cd /tmp
rm -f cert.out cert.status cert.done cert-health.out
(set +e; tailscale cert %[1]s >cert.out 2>&1; echo $? >cert.status; touch cert.done) &
certpid=$!
for i in $(seq 1 60); do
	if tailscale status --json | grep -F "Fetching TLS certificate" >cert-health.out; then
		break
	fi
	if [ -e cert.done ]; then
		break
	fi
	sleep 0.1
done
wait "$certpid" || true
cat cert.out
if [ "$(cat cert.status)" != "0" ]; then
	exit "$(cat cert.status)"
fi
test -s cert-health.out
`, qdomain)
}
