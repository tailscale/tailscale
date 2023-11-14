// The tsidp command is an OpenID Connect Identity Provider server.
package main

import (
	"context"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	"tailscale.com/client/tailscale"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/tsweb"
	"tailscale.com/types/key"
	"tailscale.com/types/lazy"
	"tailscale.com/types/logger"
	"tailscale.com/types/views"
	"tailscale.com/util/mak"
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

	lazySigningKey lazy.SyncValue[*signingKey]
	lazySigner     lazy.SyncValue[jose.Signer]

	mu sync.Mutex // guards the fields below

	code        map[string]*authRequest
	accessToken map[string]*authRequest
}

type authRequest struct {
	nonce       string
	redirectURI string

	who       *apitype.WhoIsResponse
	validTill time.Time
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
		who, err := s.lc.WhoIs(r.Context(), r.RemoteAddr)
		if err != nil {
			log.Printf("Error getting WhoIs: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		uq := r.URL.Query()
		code := must.Get(readHex())
		ar := &authRequest{
			nonce:       uq.Get("nonce"),
			who:         who,
			redirectURI: uq.Get("redirect_uri"),
		}

		s.mu.Lock()
		mak.Set(&s.code, code, ar)
		s.mu.Unlock()

		q := make(url.Values)
		q.Set("code", code)
		q.Set("state", uq.Get("state"))
		u := uq.Get("redirect_uri") + "?" + q.Encode()
		log.Printf("Redirecting to %q", u)

		http.Redirect(w, r, u, http.StatusFound)
		return
	}

	if r.URL.Path == "/userinfo" {
		s.serveUserInfo(w, r)
		return
	}

	if r.URL.Path == "/token" {
		s.serveToken(w, r)
		return
	}
	http.Error(w, "tsidp: not found", http.StatusNotFound)
}

func (s *idpServer) serveUserInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "tsidp: method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tk, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		http.Error(w, "tsidp: invalid Authorization header", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	ar, ok := s.accessToken[tk]
	s.mu.Unlock()
	if !ok {
		http.Error(w, "tsidp: invalid token", http.StatusBadRequest)
		return
	}
	if ar.validTill.Before(time.Now()) {
		http.Error(w, "tsidp: token expired", http.StatusBadRequest)
		s.mu.Lock()
		delete(s.accessToken, tk)
		s.mu.Unlock()
	}

	ui := userInfo{}
	if ar.who.Node.IsTagged() {
		http.Error(w, "tsidp: tagged nodes not supported", http.StatusBadRequest)
		return
	}
	ui.Sub = ar.who.Node.User.String()
	ui.Name = ar.who.UserProfile.DisplayName
	ui.Email = ar.who.UserProfile.LoginName
	ui.Picture = ar.who.UserProfile.ProfilePicURL

	// TODO(maisem): not sure if this is the right thing to do
	ui.UserName, _, _ = strings.Cut(ar.who.UserProfile.LoginName, "@")

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(ui); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

type userInfo struct {
	Sub      string `json:"sub"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Picture  string `json:"picture"`
	UserName string `json:"username"`
}

func (s *idpServer) serveToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "tsidp: method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// TODO: check who is making the request
	if r.FormValue("grant_type") != "authorization_code" {
		http.Error(w, "tsidp: grant_type not supported", http.StatusBadRequest)
		return
	}
	code := r.FormValue("code")
	if code == "" {
		http.Error(w, "tsidp: code is required", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	ar, ok := s.code[code]
	delete(s.code, code)
	s.mu.Unlock()
	if !ok {
		http.Error(w, "tsidp: code not found", http.StatusBadRequest)
		return
	}
	if ar.redirectURI != r.FormValue("redirect_uri") {
		http.Error(w, "tsidp: redirect_uri mismatch", http.StatusBadRequest)
		return
	}
	signer, err := s.oidcSigner()
	if err != nil {
		log.Printf("Error getting signer: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jti, err := readHex()
	if err != nil {
		log.Printf("Error reading hex: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	who := ar.who

	// TODO(maisem): not sure if this is the right thing to do
	userName, _, _ := strings.Cut(ar.who.UserProfile.LoginName, "@")
	n := who.Node.View()
	if n.IsTagged() {
		http.Error(w, "tsidp: tagged nodes not supported", http.StatusBadRequest)
		return
	}

	now := time.Now()
	_, tcd, _ := strings.Cut(n.Name(), ".")
	tsClaims := tailscaleClaims{
		Claims: jwt.Claims{
			Audience:  jwt.Audience{"unused"},
			Expiry:    jwt.NewNumericDate(now.Add(5 * time.Minute)),
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(now),
			Issuer:    s.serverURL,
			NotBefore: jwt.NewNumericDate(now),
			Subject:   n.User().String(),
		},
		Nonce:     ar.nonce,
		Key:       n.Key(),
		Addresses: n.Addresses(),
		NodeID:    n.ID(),
		NodeName:  n.Name(),
		Tailnet:   tcd,
		UserID:    n.User(),
		Email:     who.UserProfile.LoginName,
		UserName:  userName,
	}

	// Create an OIDC token using this issuer's signer.
	token, err := jwt.Signed(signer).Claims(tsClaims).CompactSerialize()
	if err != nil {
		log.Printf("Error getting token: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	at, err := readHex()
	if err != nil {
		log.Printf("Error reading hex: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.mu.Lock()
	ar.validTill = now.Add(5 * time.Minute)
	mak.Set(&s.accessToken, at, ar)
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(oidcTokenResponse{
		AccessToken: at,
		TokenType:   "Bearer",
		ExpiresIn:   5 * 60,
		IDToken:     token,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

type oidcTokenResponse struct {
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

const (
	oidcJWKSPath   = "/.well-known/jwks.json"
	oidcConfigPath = "/.well-known/openid-configuration"
)

func (s *idpServer) oidcSigner() (jose.Signer, error) {
	return s.lazySigner.GetErr(func() (jose.Signer, error) {
		sk, err := s.oidcPrivateKey()
		if err != nil {
			return nil, err
		}
		return jose.NewSigner(jose.SigningKey{
			Algorithm: jose.RS256,
			Key:       sk.k,
		}, &jose.SignerOptions{EmbedJWK: false, ExtraHeaders: map[jose.HeaderKey]interface{}{
			jose.HeaderType: "JWT",
			"kid":           fmt.Sprint(sk.kid),
		}})
	})
}

func (s *idpServer) oidcPrivateKey() (*signingKey, error) {
	return s.lazySigningKey.GetErr(func() (*signingKey, error) {
		var sk signingKey
		b, err := os.ReadFile("oidc-key.json")
		if err == nil {
			if err := sk.UnmarshalJSON(b); err == nil {
				return &sk, nil
			} else {
				log.Printf("Error unmarshaling key: %v", err)
			}
		}
		id, k := mustGenRSAKey(2048)
		sk.k = k
		sk.kid = id
		b, err = sk.MarshalJSON()
		if err != nil {
			log.Fatalf("Error marshaling key: %v", err)
		}
		if err := os.WriteFile("oidc-key.json", b, 0600); err != nil {
			log.Fatalf("Error writing key: %v", err)
		}
		return &sk, nil
	})
}

func (s *idpServer) serveJWKS(w http.ResponseWriter, r *http.Request) error {
	if r.URL.Path != oidcJWKSPath {
		return tsweb.Error(404, "", nil)
	}
	w.Header().Set("Content-Type", "application/json")
	sk, err := s.oidcPrivateKey()
	if err != nil {
		return tsweb.Error(500, err.Error(), err)
	}
	// TODO(maisem): maybe only marshal this once and reuse?
	// TODO(maisem): implement key rotation.
	je := json.NewEncoder(w)
	je.SetIndent("", "  ")
	if err := je.Encode(jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:       sk.k.Public(),
				Algorithm: string(jose.RS256),
				Use:       "sig",
				KeyID:     fmt.Sprint(sk.kid),
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
	TokenEndpoint                    string              `json:"token_endpoint,omitempty"`
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
	Nonce      string                    `json:"nonce,omitempty"` // the nonce from the request
	Key        key.NodePublic            `json:"key"`             // the node public key
	Addresses  views.Slice[netip.Prefix] `json:"addresses"`       // the Tailscale IPs of the node
	NodeID     tailcfg.NodeID            `json:"nid"`             // the stable node ID
	NodeName   string                    `json:"node"`            // name of the node
	Tailnet    string                    `json:"tailnet"`         // tailnet (like tail-scale.ts.net)

	// Tags is the list of tags the node is tagged with prefixed with the Tailnet name.
	Tags []string `json:"tags,omitempty"` // the tags on the node (like alice.github:tag:foo or example.com:tag:foo)

	// Email is the emailish of the user prefixed with the Tailnet name.
	Email  string         `json:"email,omitempty"` // user emailish (like alice.github:alice@github or example.com:bob@example.com)
	UserID tailcfg.UserID `json:"uid,omitempty"`   // user legacy id

	UserName string `json:"username,omitempty"` // user name
}

var (
	openIDSupportedClaims = views.SliceOf([]string{
		// Standard claims, these correspond to fields in jwt.Claims.
		"sub", "aud", "exp", "iat", "iss", "jti", "nbf", "username", "email",

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
	je := json.NewEncoder(w)
	je.SetIndent("", "  ")
	if err := je.Encode(openIDProviderMetadata{
		Issuer:                           s.serverURL,
		JWKS_URI:                         s.serverURL + oidcJWKSPath,
		UserInfoEndpoint:                 s.serverURL + "/userinfo",
		AuthorizationEndpoint:            s.serverURL + "/authorize", // TODO: add /<nodeid> suffix
		TokenEndpoint:                    s.serverURL + "/token",
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

func readHex() (string, error) {
	var proxyCred [16]byte
	if _, err := crand.Read(proxyCred[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(proxyCred[:]), nil
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

type signingKey struct {
	k   *rsa.PrivateKey
	kid uint64
}

func (sk *signingKey) MarshalJSON() ([]byte, error) {
	b := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(sk.k),
	}
	bts := pem.EncodeToMemory(&b)
	return json.Marshal(rsaPrivateKeyJSONWrapper{
		Key: base64.URLEncoding.EncodeToString(bts),
		ID:  sk.kid,
	})
}

func (sk *signingKey) UnmarshalJSON(b []byte) error {
	var wrapper rsaPrivateKeyJSONWrapper
	if err := json.Unmarshal(b, &wrapper); err != nil {
		return err
	}
	if len(wrapper.Key) == 0 {
		return nil
	}
	b64dec, err := base64.URLEncoding.DecodeString(wrapper.Key)
	if err != nil {
		return err
	}
	blk, _ := pem.Decode(b64dec)
	k, err := x509.ParsePKCS1PrivateKey(blk.Bytes)
	if err != nil {
		return err
	}
	sk.k = k
	sk.kid = wrapper.ID
	return nil
}