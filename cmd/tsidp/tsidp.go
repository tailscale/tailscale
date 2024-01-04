// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The tsidp command is an OpenID Connect Identity Provider server.
//
// See https://github.com/tailscale/tailscale/issues/10263 for background.
package main

import (
	"context"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	"tailscale.com/client/tailscale"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/envknob"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/types/key"
	"tailscale.com/types/lazy"
	"tailscale.com/types/logger"
	"tailscale.com/types/views"
	"tailscale.com/util/mak"
	"tailscale.com/util/must"
	"tailscale.com/util/rands"
)

var (
	flagVerbose            = flag.Bool("verbose", false, "be verbose")
	flagPort               = flag.Int("port", 443, "port to listen on")
	flagLocalPort          = flag.Int("local-port", -1, "allow requests from localhost")
	flagUseLocalTailscaled = flag.Bool("use-local-tailscaled", false, "use local tailscaled instead of tsnet")
)

func main() {
	flag.Parse()
	ctx := context.Background()
	if !envknob.UseWIPCode() {
		log.Fatal("cmd/tsidp is a work in progress and has not been security reviewed;\nits use requires TAILSCALE_USE_WIP_CODE=1 be set in the environment for now.")
	}

	var (
		lc  *tailscale.LocalClient
		st  *ipnstate.Status
		err error

		lns []net.Listener
	)
	if *flagUseLocalTailscaled {
		lc = &tailscale.LocalClient{}
		st, err = lc.StatusWithoutPeers(ctx)
		if err != nil {
			log.Fatalf("getting status: %v", err)
		}
		portStr := fmt.Sprint(*flagPort)
		anySuccess := false
		for _, ip := range st.TailscaleIPs {
			ln, err := net.Listen("tcp", net.JoinHostPort(ip.String(), portStr))
			if err != nil {
				log.Printf("failed to listen on %v: %v", ip, err)
				continue
			}
			anySuccess = true
			ln = tls.NewListener(ln, &tls.Config{
				GetCertificate: lc.GetCertificate,
			})
			lns = append(lns, ln)
		}
		if !anySuccess {
			log.Fatalf("failed to listen on any of %v", st.TailscaleIPs)
		}
	} else {
		ts := &tsnet.Server{
			Hostname: "idp",
		}
		if !*flagVerbose {
			ts.Logf = logger.Discard
		}
		st, err = ts.Up(ctx)
		if err != nil {
			log.Fatal(err)
		}
		lc, err = ts.LocalClient()
		if err != nil {
			log.Fatalf("getting local client: %v", err)
		}
		ln, err := ts.ListenTLS("tcp", fmt.Sprintf(":%d", *flagPort))
		if err != nil {
			log.Fatal(err)
		}
		lns = append(lns, ln)
	}

	srv := &idpServer{
		lc: lc,
	}
	if *flagPort != 443 {
		srv.serverURL = fmt.Sprintf("https://%s:%d", strings.TrimSuffix(st.Self.DNSName, "."), *flagPort)
	} else {
		srv.serverURL = fmt.Sprintf("https://%s", strings.TrimSuffix(st.Self.DNSName, "."))
	}

	log.Printf("Running tsidp at %s ...", srv.serverURL)

	if *flagLocalPort != -1 {
		log.Printf("Also running tsidp at %s ...", srv.loopbackURL)
		srv.loopbackURL = fmt.Sprintf("http://localhost:%d", *flagLocalPort)
		ln, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", *flagLocalPort))
		if err != nil {
			log.Fatal(err)
		}
		lns = append(lns, ln)
	}

	for _, ln := range lns {
		go http.Serve(ln, srv)
	}
	select {}
}

type idpServer struct {
	lc          *tailscale.LocalClient
	loopbackURL string
	serverURL   string // "https://foo.bar.ts.net"

	lazyMux        lazy.SyncValue[*http.ServeMux]
	lazySigningKey lazy.SyncValue[*signingKey]
	lazySigner     lazy.SyncValue[jose.Signer]

	mu          sync.Mutex              // guards the fields below
	code        map[string]*authRequest // keyed by random hex
	accessToken map[string]*authRequest // keyed by random hex
}

type authRequest struct {
	// localRP is true if the request is from a relying party running on the
	// same machine as the idp server. It is mutually exclusive with rpNodeID.
	localRP bool

	// rpNodeID is the NodeID of the relying party (who requested the auth, such
	// as Proxmox or Synology), not the user node who is being authenticated. It
	// is mutually exclusive with localRP.
	rpNodeID tailcfg.NodeID

	// clientID is the "client_id" sent in the authorized request.
	clientID string

	// nonce presented in the request.
	nonce string

	// redirectURI is the redirect_uri presented in the request.
	redirectURI string

	// remoteUser is the user who is being authenticated.
	remoteUser *apitype.WhoIsResponse

	// validTill is the time until which the token is valid.
	// As of 2023-11-14, it is 5 minutes.
	// TODO: add routine to delete expired tokens.
	validTill time.Time
}

func (ar *authRequest) allowRelyingParty(ctx context.Context, remoteAddr string, lc *tailscale.LocalClient) error {
	if ar.localRP {
		ra, err := netip.ParseAddrPort(remoteAddr)
		if err != nil {
			return err
		}
		if !ra.Addr().IsLoopback() {
			return fmt.Errorf("tsidp: request from non-loopback address")
		}
		return nil
	}
	who, err := lc.WhoIs(ctx, remoteAddr)
	if err != nil {
		return fmt.Errorf("tsidp: error getting WhoIs: %w", err)
	}
	if ar.rpNodeID != who.Node.ID {
		return fmt.Errorf("tsidp: token for different node")
	}
	return nil
}

func (s *idpServer) authorize(w http.ResponseWriter, r *http.Request) {
	who, err := s.lc.WhoIs(r.Context(), r.RemoteAddr)
	if err != nil {
		log.Printf("Error getting WhoIs: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	uq := r.URL.Query()

	code := rands.HexString(32)
	ar := &authRequest{
		nonce:       uq.Get("nonce"),
		remoteUser:  who,
		redirectURI: uq.Get("redirect_uri"),
		clientID:    uq.Get("client_id"),
	}

	if r.URL.Path == "/authorize/localhost" {
		ar.localRP = true
	} else {
		var ok bool
		ar.rpNodeID, ok = parseID[tailcfg.NodeID](strings.TrimPrefix(r.URL.Path, "/authorize/"))
		if !ok {
			http.Error(w, "tsidp: invalid node ID suffix after /authorize/", http.StatusBadRequest)
			return
		}
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
}

func (s *idpServer) newMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc(oidcJWKSPath, s.serveJWKS)
	mux.HandleFunc(oidcConfigPath, s.serveOpenIDConfig)
	mux.HandleFunc("/authorize/", s.authorize)
	mux.HandleFunc("/userinfo", s.serveUserInfo)
	mux.HandleFunc("/token", s.serveToken)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			io.WriteString(w, "<html><body><h1>Tailscale OIDC IdP</h1>")
			return
		}
		http.Error(w, "tsidp: not found", http.StatusNotFound)
	})
	return mux
}

func (s *idpServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%v %v", r.Method, r.URL)
	s.lazyMux.Get(s.newMux).ServeHTTP(w, r)
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
	if err := ar.allowRelyingParty(r.Context(), r.RemoteAddr, s.lc); err != nil {
		log.Printf("Error allowing relying party: %v", err)
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	if ar.validTill.Before(time.Now()) {
		http.Error(w, "tsidp: token expired", http.StatusBadRequest)
		s.mu.Lock()
		delete(s.accessToken, tk)
		s.mu.Unlock()
	}

	ui := userInfo{}
	if ar.remoteUser.Node.IsTagged() {
		http.Error(w, "tsidp: tagged nodes not supported", http.StatusBadRequest)
		return
	}
	ui.Sub = ar.remoteUser.Node.User.String()
	ui.Name = ar.remoteUser.UserProfile.DisplayName
	ui.Email = ar.remoteUser.UserProfile.LoginName
	ui.Picture = ar.remoteUser.UserProfile.ProfilePicURL

	// TODO(maisem): not sure if this is the right thing to do
	ui.UserName, _, _ = strings.Cut(ar.remoteUser.UserProfile.LoginName, "@")

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
	if ok {
		delete(s.code, code)
	}
	s.mu.Unlock()
	if !ok {
		http.Error(w, "tsidp: code not found", http.StatusBadRequest)
		return
	}
	if err := ar.allowRelyingParty(r.Context(), r.RemoteAddr, s.lc); err != nil {
		log.Printf("Error allowing relying party: %v", err)
		http.Error(w, err.Error(), http.StatusForbidden)
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
	jti := rands.HexString(32)
	who := ar.remoteUser

	// TODO(maisem): not sure if this is the right thing to do
	userName, _, _ := strings.Cut(ar.remoteUser.UserProfile.LoginName, "@")
	n := who.Node.View()
	if n.IsTagged() {
		http.Error(w, "tsidp: tagged nodes not supported", http.StatusBadRequest)
		return
	}

	now := time.Now()
	_, tcd, _ := strings.Cut(n.Name(), ".")
	tsClaims := tailscaleClaims{
		Claims: jwt.Claims{
			Audience:  jwt.Audience{ar.clientID},
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
	if ar.localRP {
		tsClaims.Issuer = s.loopbackURL
	}

	// Create an OIDC token using this issuer's signer.
	token, err := jwt.Signed(signer).Claims(tsClaims).CompactSerialize()
	if err != nil {
		log.Printf("Error getting token: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	at := rands.HexString(32)
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
		}, &jose.SignerOptions{EmbedJWK: false, ExtraHeaders: map[jose.HeaderKey]any{
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

func (s *idpServer) serveJWKS(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != oidcJWKSPath {
		http.Error(w, "tsidp: not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	sk, err := s.oidcPrivateKey()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
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
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	return
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

	// Email is the "emailish" value with an '@' sign. It might not be a valid email.
	Email  string         `json:"email,omitempty"` // user emailish (like "alice@github" or "bob@example.com")
	UserID tailcfg.UserID `json:"uid,omitempty"`

	// UserName is the local part of Email (without '@' and domain).
	// It is a temporary (2023-11-15) hack during development.
	// We should probably let this be configured via grants.
	UserName string `json:"username,omitempty"`
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

func (s *idpServer) serveOpenIDConfig(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != oidcConfigPath {
		http.Error(w, "tsidp: not found", http.StatusNotFound)
		return
	}
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		log.Printf("Error parsing remote addr: %v", err)
		return
	}
	var authorizeEndpoint string
	rpEndpoint := s.serverURL
	if who, err := s.lc.WhoIs(r.Context(), r.RemoteAddr); err == nil {
		authorizeEndpoint = fmt.Sprintf("%s/authorize/%d", s.serverURL, who.Node.ID)
	} else if ap.Addr().IsLoopback() {
		rpEndpoint = s.loopbackURL
		authorizeEndpoint = fmt.Sprintf("%s/authorize/localhost", s.serverURL)
	} else {
		log.Printf("Error getting WhoIs: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	je := json.NewEncoder(w)
	je.SetIndent("", "  ")
	if err := je.Encode(openIDProviderMetadata{
		AuthorizationEndpoint:            authorizeEndpoint,
		Issuer:                           rpEndpoint,
		JWKS_URI:                         rpEndpoint + oidcJWKSPath,
		UserInfoEndpoint:                 rpEndpoint + "/userinfo",
		TokenEndpoint:                    rpEndpoint + "/token",
		ScopesSupported:                  openIDSupportedScopes,
		ResponseTypesSupported:           openIDSupportedReponseTypes,
		SubjectTypesSupported:            openIDSupportedSubjectTypes,
		ClaimsSupported:                  openIDSupportedClaims,
		IDTokenSigningAlgValuesSupported: openIDSupportedSigningAlgos,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
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

// parseID takes a string input and returns a typed IntID T and true, or a zero
// value and false if the input is unhandled syntax or out of a valid range.
func parseID[T ~int64](input string) (_ T, ok bool) {
	if input == "" {
		return 0, false
	}
	i, err := strconv.ParseInt(input, 10, 64)
	if err != nil {
		return 0, false
	}
	if i < 0 {
		return 0, false
	}
	return T(i), true
}
