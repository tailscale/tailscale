// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !ts_omit_acme

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path"
	"runtime"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/hostinfo"
	"tailscale.com/ipn"
	"tailscale.com/version/distro"
)

func init() {
	maybeConfigSynologyCertCmd = synologyConfigureCertCmd
}

func synologyConfigureCertCmd() *ffcli.Command {
	if runtime.GOOS != "linux" || distro.Get() != distro.Synology {
		return nil
	}
	return &ffcli.Command{
		Name:       "synology-cert",
		Exec:       runConfigureSynologyCert,
		ShortHelp:  "Configure Synology with a TLS certificate for your tailnet",
		ShortUsage: "synology-cert [--domain <domain>]",
		LongHelp: strings.TrimSpace(`
This command is intended to run periodically as root on a Synology device to
create or refresh the TLS certificate for the tailnet domain.

See: https://tailscale.com/kb/1153/enabling-https
`),
		FlagSet: (func() *flag.FlagSet {
			fs := newFlagSet("synology-cert")
			fs.StringVar(&synologyConfigureCertArgs.domain, "domain", "", "Tailnet domain to create or refresh certificates for. Ignored if only one domain exists.")
			return fs
		})(),
	}
}

var synologyConfigureCertArgs struct {
	domain string
}

func runConfigureSynologyCert(ctx context.Context, args []string) error {
	if len(args) > 0 {
		return errors.New("unknown arguments")
	}
	if runtime.GOOS != "linux" || distro.Get() != distro.Synology {
		return errors.New("only implemented on Synology")
	}
	if uid := os.Getuid(); uid != 0 {
		return fmt.Errorf("must be run as root, not %q (%v)", os.Getenv("USER"), uid)
	}
	hi := hostinfo.New()
	isDSM6 := strings.HasPrefix(hi.DistroVersion, "6.")
	isDSM7 := strings.HasPrefix(hi.DistroVersion, "7.")
	if !isDSM6 && !isDSM7 {
		return fmt.Errorf("unsupported DSM version %q", hi.DistroVersion)
	}

	domain := synologyConfigureCertArgs.domain
	if st, err := localClient.Status(ctx); err == nil {
		if st.BackendState != ipn.Running.String() {
			return fmt.Errorf("Tailscale is not running.")
		} else if len(st.CertDomains) == 0 {
			return fmt.Errorf("TLS certificate support is not enabled/configured for your tailnet.")
		} else if len(st.CertDomains) == 1 {
			if domain != "" && domain != st.CertDomains[0] {
				log.Printf("Ignoring supplied domain %q, TLS certificate will be created for %q.\n", domain, st.CertDomains[0])
			}
			domain = st.CertDomains[0]
		} else {
			var found bool
			for _, d := range st.CertDomains {
				if d == domain {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("Domain %q was not one of the valid domain options: %q.", domain, st.CertDomains)
			}
		}
	}

	// Check for an existing certificate, and replace it if it already exists
	var id string
	certs, err := listCerts(ctx, synowebapiCommand{})
	if err != nil {
		return err
	}
	for _, c := range certs {
		if c.Subject.CommonName == domain {
			id = c.ID
			break
		}
	}

	certPEM, keyPEM, err := localClient.CertPair(ctx, domain)
	if err != nil {
		return err
	}

	// Certs have to be written to file for the upload command to work.
	tmpDir, err := os.MkdirTemp("", "")
	if err != nil {
		return fmt.Errorf("can't create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)
	keyFile := path.Join(tmpDir, "key.pem")
	os.WriteFile(keyFile, keyPEM, 0600)
	certFile := path.Join(tmpDir, "cert.pem")
	os.WriteFile(certFile, certPEM, 0600)

	if err := uploadCert(ctx, synowebapiCommand{}, certFile, keyFile, id); err != nil {
		return err
	}

	return nil
}

type subject struct {
	CommonName string `json:"common_name"`
}

type certificateInfo struct {
	ID      string  `json:"id"`
	Desc    string  `json:"desc"`
	Subject subject `json:"subject"`
}

// listCerts fetches a list of the certificates that DSM knows about
func listCerts(ctx context.Context, c synoAPICaller) ([]certificateInfo, error) {
	rawData, err := c.Call(ctx, "SYNO.Core.Certificate.CRT", "list", nil)
	if err != nil {
		return nil, err
	}

	var payload struct {
		Certificates []certificateInfo `json:"certificates"`
	}
	if err := json.Unmarshal(rawData, &payload); err != nil {
		return nil, fmt.Errorf("decoding certificate list response payload: %w", err)
	}

	return payload.Certificates, nil
}

// uploadCert creates or replaces a certificate. If id is given, it will attempt to replace the certificate with that ID.
func uploadCert(ctx context.Context, c synoAPICaller, certFile, keyFile string, id string) error {
	params := map[string]string{
		"key_tmp":  keyFile,
		"cert_tmp": certFile,
		"desc":     "Tailnet Certificate",
	}
	if id != "" {
		params["id"] = id
	}

	rawData, err := c.Call(ctx, "SYNO.Core.Certificate", "import", params)
	if err != nil {
		return err
	}

	var payload struct {
		NewID string `json:"id"`
	}
	if err := json.Unmarshal(rawData, &payload); err != nil {
		return fmt.Errorf("decoding certificate upload response payload: %w", err)
	}
	log.Printf("Tailnet Certificate uploaded with ID %q.", payload.NewID)

	return nil

}

type synoAPICaller interface {
	Call(context.Context, string, string, map[string]string) (json.RawMessage, error)
}

type apiResponse struct {
	Success bool            `json:"success"`
	Error   *apiError       `json:"error,omitempty"`
	Data    json.RawMessage `json:"data"`
}

type apiError struct {
	Code   int64  `json:"code"`
	Errors string `json:"errors"`
}

// synowebapiCommand implements synoAPICaller using the /usr/syno/bin/synowebapi binary. Must be run as root.
type synowebapiCommand struct{}

func (s synowebapiCommand) Call(ctx context.Context, api, method string, params map[string]string) (json.RawMessage, error) {
	args := []string{"--exec", fmt.Sprintf("api=%s", api), fmt.Sprintf("method=%s", method)}

	for k, v := range params {
		args = append(args, fmt.Sprintf("%s=%q", k, v))
	}

	out, err := exec.CommandContext(ctx, "/usr/syno/bin/synowebapi", args...).Output()
	if err != nil {
		return nil, fmt.Errorf("calling %q method of %q API: %v, %s", method, api, err, out)
	}

	var payload apiResponse
	if err := json.Unmarshal(out, &payload); err != nil {
		return nil, fmt.Errorf("decoding response json from %q method of %q API: %w", method, api, err)
	}

	if payload.Error != nil {
		return nil, fmt.Errorf("error response from %q method of %q API: %v", method, api, payload.Error)
	}

	return payload.Data, nil
}
