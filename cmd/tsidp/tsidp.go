// The tsidp command is an OpenID Connect Identity Provider server.
package main

import (
	"context"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"

	"github.com/golang-jwt/jwt"
	"gopkg.in/square/go-jose.v2"
	"tailscale.com/client/tailscale"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/tsweb"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/views"
	"tailscale.com/util/must"
)

var (
	flagVerbose = flag.Bool("verbose", false, "be verbose")
)

func main() {
	flag.Parse()
	ctx := context.Background()
	ts := &tsnet.Server{
		Hostname: "idp",
	}
	if !*flagVerbose {
		ts.Logf = logger.Discard
	}
	st, err := ts.Up(ctx)
	if err != nil {
		log.Fatal(err)
	}
	lc, err := ts.LocalClient()
	if err != nil {
		log.Fatalf("getting local client: %v", err)
	}

	srv := &idpServer{
		lc:        lc,
		serverURL: "https://" + strings.TrimSuffix(st.Self.DNSName, "."),
	}
	log.Printf("Running tsidp at %s ...", srv.serverURL)

	ln, err := ts.ListenTLS("tcp", ":443")
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(http.Serve(ln, srv))
}

type idpServer struct {
	lc        *tailscale.LocalClient
	serverURL string // "https://foo.bar.ts.net"

	oidcSignerInitOnce sync.Once
	oidcSignerLazy     jose.Signer
	oidcSignerError    error
}

func (s *idpServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%v %v", r.Method, r.URL)

	if r.URL.Path == oidcJWKSPath {
		if err := s.serveJWKS(w, r); err != nil {
			log.Printf("Error serving JWKS: %v", err)
		}
		return
	}
	if r.URL.Path == oidcConfigPath {
		if err := s.serveOpenIDConfig(w, r); err != nil {
			log.Printf("Error serving OpenID config: %v", err)
		}
		return
	}
	if r.URL.Path == "/" {
		io.WriteString(w, "<html><body><h1>Tailscale OIDC IdP</h1>")
		return
	}

	if r.URL.Path == "/authorize" {
		redir := r.URL.Query().Get("redirect_uri")

		http.Redirect(w, r, redir, http.StatusFound)
		return
	}
	http.Error(w, "tsidp: not found", http.StatusNotFound)
}

const (
	oidcJWKSPath   = "/.well-known/jwks.json"
	oidcConfigPath = "/.well-known/openid-configuration"
)

func (s *idpServer) oidcSigner() (jose.Signer, error) {
	s.oidcSignerInitOnce.Do(s.oidcSignerInit)
	return s.oidcSignerLazy, s.oidcSignerError
}

func (s *idpServer) oidcSignerInit() {
	id, k := s.oidcPrivateKey()
	s.oidcSignerLazy, s.oidcSignerError = jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       k,
	}, &jose.SignerOptions{EmbedJWK: false, ExtraHeaders: map[jose.HeaderKey]interface{}{
		jose.HeaderType: "JWT",
		"kid":           fmt.Sprint(id),
	}})
}

func (s *idpServer) oidcPrivateKey() (id uint64, k *rsa.PrivateKey) {
	id, k = mustGenRSAKey(2048)
	return
}

func (s *idpServer) serveJWKS(w http.ResponseWriter, r *http.Request) error {
	if r.URL.Path != oidcJWKSPath {
		return tsweb.Error(404, "", nil)
	}
	w.Header().Set("Content-Type", "application/json")
	id, k := s.oidcPrivateKey()
	// TODO(maisem): maybe only marshal this once and reuse?
	// TODO(maisem): implement key rotation.
	if err := json.NewEncoder(w).Encode(jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:       k.Public(),
				Algorithm: string(jose.RS256),
				Use:       "sig",
				KeyID:     fmt.Sprint(id),
			},
		},
	}); err != nil {
		return tsweb.Error(500, err.Error(), err)
	}
	return nil
}

// openIDProviderMetadata is a partial representation of
// https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata.
type openIDProviderMetadata struct {
	Issuer                           string              `json:"issuer"`
	AuthorizationEndpoint            string              `json:"authorization_endpoint,omitempty"`
	UserInfoEndpoint                 string              `json:"userinfo_endpoint,omitempty"`
	JWKS_URI                         string              `json:"jwks_uri"`
	ScopesSupported                  views.Slice[string] `json:"scopes_supported"`
	ResponseTypesSupported           views.Slice[string] `json:"response_types_supported"`
	SubjectTypesSupported            views.Slice[string] `json:"subject_types_supported"`
	ClaimsSupported                  views.Slice[string] `json:"claims_supported"`
	IDTokenSigningAlgValuesSupported views.Slice[string] `json:"id_token_signing_alg_values_supported"`
	// TODO(maisem): maybe add other fields?
	// Currently we fill out the REQUIRED fields, scopes_supported and claims_supported.
}

type tailscaleClaims struct {
	jwt.Claims `json:",inline"`
	Key        key.NodePublic            `json:"key"`       // the node public key
	Addresses  views.Slice[netip.Prefix] `json:"addresses"` // the Tailscale IPs of the node
	NodeID     tailcfg.NodeID            `json:"nid"`       // the stable node ID
	NodeName   string                    `json:"node"`      // name of the node
	Tailnet    string                    `json:"tailnet"`   // tailnet (like tail-scale.ts.net)

	// Tags is the list of tags the node is tagged with prefixed with the Tailnet name.
	Tags []string `json:"tags,omitempty"` // the tags on the node (like alice.github:tag:foo or example.com:tag:foo)

	// User is the emailish of the user prefixed with the Tailnet name.
	User   string         `json:"user,omitempty"` // user emailish (like alice.github:alice@github or example.com:bob@example.com)
	UserID tailcfg.UserID `json:"uid,omitempty"`  // user legacy id
}

var (
	openIDSupportedClaims = views.SliceOf([]string{
		// Standard claims, these correspond to fields in jwt.Claims.
		"sub", "aud", "exp", "iat", "iss", "jti", "nbf",

		// Tailscale claims, these correspond to fields in tailscaleClaims.
		"key", "addresses", "nid", "node", "tailnet", "tags", "user", "uid",
	})

	// As defined in the OpenID spec this should be "openid".
	openIDSupportedScopes = views.SliceOf([]string{"openid", "email", "profile"})

	// We only support getting the id_token.
	openIDSupportedReponseTypes = views.SliceOf([]string{"id_token", "code"})

	// The type of the "sub" field in the JWT, which means it is globally unique identifier.
	// The other option is "pairwise", which means the identifier is different per receiving 3p.
	openIDSupportedSubjectTypes = views.SliceOf([]string{"public"})

	// The algo used for signing. The OpenID spec says "The algorithm RS256 MUST be included."
	// https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
	openIDSupportedSigningAlgos = views.SliceOf([]string{string(jose.RS256)})
)

func (s *idpServer) serveOpenIDConfig(w http.ResponseWriter, r *http.Request) error {
	if r.URL.Path != oidcConfigPath {
		return tsweb.Error(404, "", nil)
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(io.MultiWriter(w, os.Stderr)).Encode(openIDProviderMetadata{
		Issuer:                           s.serverURL + "/",
		JWKS_URI:                         s.serverURL + oidcJWKSPath,
		UserInfoEndpoint:                 s.serverURL + "/userinfo",
		AuthorizationEndpoint:            s.serverURL + "/authorize", // TODO: add /<nodeid> suffix
		ScopesSupported:                  openIDSupportedScopes,
		ResponseTypesSupported:           openIDSupportedReponseTypes,
		SubjectTypesSupported:            openIDSupportedSubjectTypes,
		ClaimsSupported:                  openIDSupportedClaims,
		IDTokenSigningAlgValuesSupported: openIDSupportedSigningAlgos,
	}); err != nil {
		log.Printf("Error encoding JSON: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	return nil
}

const (
	minimumRSAKeySize = 2048
)

// mustGenRSAKey generates a new RSA key with the provided number of bits. It
// panics on failure. bits must be at least minimumRSAKeySizeBytes * 8.
func mustGenRSAKey(bits int) (kid uint64, k *rsa.PrivateKey) {
	if bits < minimumRSAKeySize {
		panic("request to generate a too-small RSA key")
	}
	kid = must.Get(readUint64(crand.Reader))
	k = must.Get(rsa.GenerateKey(crand.Reader, bits))
	return
}

// readUint64 reads from r until 8 bytes represent a non-zero uint64.
func readUint64(r io.Reader) (uint64, error) {
	for {
		var b [8]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, err
		}
		if v := binary.BigEndian.Uint64(b[:]); v != 0 {
			return v, nil
		}
	}
}

// rsaPrivateKeyJSONWrapper is the the JSON serialization
// format used by RSAPrivateKey.
type rsaPrivateKeyJSONWrapper struct {
	Key string
	ID  uint64
}

func marshalKeyJSON(k *rsa.PrivateKey, kid uint64) ([]byte, error) {
	b := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(k),
	}
	bts := pem.EncodeToMemory(&b)
	return json.Marshal(rsaPrivateKeyJSONWrapper{
		Key: base64.URLEncoding.EncodeToString(bts),
		ID:  kid,
	})
}

func unmarshalKeyJSON(b []byte) (*rsa.PrivateKey, uint64, error) {
	var wrapper rsaPrivateKeyJSONWrapper
	if err := json.Unmarshal(b, &wrapper); err != nil {
		return nil, 0, err
	}
	if len(wrapper.Key) == 0 {
		return nil, 0, nil
	}
	b64dec, err := base64.URLEncoding.DecodeString(wrapper.Key)
	if err != nil {
		return nil, 0, err
	}
	blk, _ := pem.Decode(b64dec)
	k, err := x509.ParsePKCS1PrivateKey(blk.Bytes)
	return k, wrapper.ID, err
}
