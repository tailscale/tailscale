// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package taildrop

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
	"tailscale.com/feature/taildrop/taildroptype"
	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/util/rands"
)

// Consent lets the receiving device's owner approve each inbound Taildrop
// transfer before any file data is sent.
//
// If the recipient supports it, the sender first POSTs to /v0/put-request/{filename}
// with a transaction ID, file size, and SHA-256 hash. Approval returns an HMAC token
// binding those fields to the sender, filename, expiry, and a random nonce. The
// sender presents the token on the subsequent PUT, which the receiver verifies
// before reading a single body byte.
//
// The HMAC key never leaves this node, so a token is only meaningful to the node
// that issued it. The nonce keys a server-side record carrying a consumed flag,
// which is what actually enforces one approval per delivery.
//
// Cross-user requests require AllowExternalTaildrop; otherwise they are rejected
// without prompting. Tagged endpoints also require opt-in and consent; unsigned
// nodes cannot participate. Same-user untagged transfers are always implicitly
// allowed, independent of new preferences or
// the testing override. See [putAuthFor].

const (
	// consentTokenTTL is how long an approved consent token remains usable.
	consentTokenTTL = 5 * time.Minute

	// consentPendingTTL is how long a request may sit awaiting a decision
	// before the sender has to ask again.
	consentPendingTTL = 5 * time.Minute

	// Bound the number of simultaneous prompts awaiting an owner decision.
	maxConsentPeerFiles = 8
	maxConsentFiles     = 16

	// Retain transaction history separately so decisions and expiry free prompt
	// slots without allowing repeated polls to resurrect old prompts.
	consentTerminalTTL    = 5 * time.Minute
	maxConsentPeerHistory = 256
	maxConsentHistory     = 1024
)

// Consent HTTP headers, sent by the sender on a consented PUT.
const (
	hdrConsentTxID    = "X-Taildrop-Txid"
	hdrConsentToken   = "X-Taildrop-Token"
	hdrConsentNonce   = "X-Taildrop-Nonce"
	hdrConsentExpires = "X-Taildrop-Expires"

	// hdrConsentError is set by the receiver on a response it rejected on
	// consent grounds, so the sender can tell that apart from the other
	// reasons a PUT may be refused: an ordinary 403 (not authorized) or 409
	// (file already exists) says nothing about consent and must not
	// invalidate a token the user has already approved.
	hdrConsentError = "X-Taildrop-Consent-Error"
)

// PutRequest is the JSON body of a POST /v0/put-request/{filename} request.
type PutRequest struct {
	Size int64  `json:"size"` // in bytes
	TxID string `json:"txid"`
	Hash string `json:"hash"` // lowercase SHA-256 hex digest

}

func (r PutRequest) validate() error {
	if r.Size < 0 || len(r.TxID) == 0 || len(r.TxID) > 128 || strings.ContainsAny(r.TxID, "\x00\r\n") {
		return errors.New("invalid transfer size or transaction ID")
	}
	b, err := hex.DecodeString(r.Hash)
	if err != nil || len(b) != sha256.Size || r.Hash != strings.ToLower(r.Hash) {
		return errors.New("invalid SHA-256 hash")
	}
	return nil
}

// ConsentToken authorizes exactly one delivery of one file. It is the JSON body
// of a successful POST /v0/put-request/{filename} response.
type ConsentToken struct {
	TxID      string    `json:"txid"`
	Hash      string    `json:"hash"`
	Token     string    `json:"token"`      // base64url of the 32-byte HMAC
	Nonce     string    `json:"nonce"`      // base64url of the 32-byte nonce
	ExpiresAt time.Time `json:"expires_at"` // RFC 3339
}

// ConsentState is the state of a consent request, as reported to both the
// sending peer and to local clients.
type ConsentState string

const (
	ConsentNotAllowed ConsentState = "notallowed"
	// ConsentNotRequired means the receiver does not require consent, so the
	// sender should proceed with an ordinary PUT.
	ConsentNotRequired ConsentState = "notRequired"

	// ConsentPending means the device owner has not yet decided.
	ConsentPending ConsentState = "pending"

	// ConsentApproved means the owner approved and a token was issued.
	ConsentApproved ConsentState = "approved"

	// ConsentDenied means the owner declined, or the request expired
	// undecided.
	ConsentDenied ConsentState = "denied"
)

// Errors reported by [manager.beginConsentedPut]. They are distinct so the
// PeerAPI handler can map each to the HTTP status the sender needs in order to
// decide whether to re-request consent, retry, or give up.
var (
	ErrConsentNotAllowed   = errors.New("taildrop: this user has not enabled Taildrop from other users; ask them to enable it on this device")
	ErrConsentHashMismatch = errors.New("taildrop: file mismatch")
	ErrConsentRequired     = errors.New("taildrop: consent required")
	ErrConsentExpired      = errors.New("taildrop: consent expired")
	ErrConsentUnknown      = errors.New("taildrop: no matching consent")
	ErrConsentConsumed     = errors.New("taildrop: consent already used")
	ErrConsentMismatch     = errors.New("taildrop: consent does not match transfer")
	ErrConsentInvalid      = errors.New("taildrop: invalid consent token")
	ErrConsentMalformed    = errors.New("taildrop: malformed consent headers")
	ErrConsentDenied       = errors.New("taildrop: transfer declined")
	ErrConsentLimit        = errors.New("taildrop: too many consent requests; try again later")
)

// consentRecord is the receiver's record of one issued [ConsentToken].
//
// Records are in-memory only. Losing them across a restart just means the
// sender must ask for consent again.
type consentRecord struct {
	TxID      string
	Hash      string
	SenderID  tailcfg.StableNodeID
	Filename  string
	Size      int64
	Nonce     [32]byte
	ExpiresAt time.Time

	// BytesReceived is how much of the file has been durably received. It
	// exists so an interrupted transfer can resume under the same consent:
	// the record is not consumed until the whole file has arrived.
	BytesReceived int64

	// InFlight is set while a PUT is actively using this record, so two
	// concurrent PUTs can't both slip through before either is consumed.
	InFlight bool

	// Consumed is set once the full file has been received. A consumed record
	// is never usable again.
	Consumed bool
}

// consentFile is the file awaiting consent.
type consentFile struct {
	used  bool
	txid  string
	hash  string
	name  string
	size  int64
	token *ConsentToken // non-nil once the request is approved
}

// consentRequest tracks the decision for one inbound file.
type consentRequest struct {
	id         string
	senderID   tailcfg.StableNodeID
	senderName string
	file       consentFile
	requested  time.Time
	expires    time.Time

	decided        bool
	allowed        bool
	expiryNotified bool
}

func (g *consentRequest) asNotify() taildroptype.ConsentRequest {
	req := taildroptype.ConsentRequest{
		RequestID: g.id,
		PeerID:    g.senderID,
		PeerName:  g.senderName,
		Files:     []taildroptype.ConsentFile{{Name: g.file.name, Size: g.file.size}},
		TotalSize: g.file.size,
		Requested: g.requested,
		Expires:   g.expires,
	}
	return req
}

// consentStore holds pending consent requests and issued consent records.
//
// Expired transactions remain as bounded tombstones for consentTerminalTTL.
// The expiry worker publishes removals even when there is no peer activity.
type consentStore struct {
	mu            sync.Mutex
	requests      map[string]*consentRequest  // by request ID
	records       map[[32]byte]*consentRecord // by nonce
	secret        [32]byte                    // HMAC key; valid iff haveSecret
	haveSecret    bool
	admission     *rate.Limiter // global new-file rate; polls do not consume tokens
	expiryChanged bool          // an unannounced prompt was removed by garbage collection
}

// outboundConsentKey identifies one of this node's own outbound transfers, for
// caching the consent token a peer issued us.
type outboundConsentKey struct {
	TxID     string
	Hash     string
	Peer     tailcfg.StableNodeID
	Filename string
	Size     int64
}

// outboundConsentCache bounds approvals retained by abandoned or failed sends.
// Reads and writes prune all expired entries, including transactions that are
// never looked up again. Idle caches retain at most maxOutboundConsent entries.
// All fields are protected by mu.
type outboundConsentCache struct {
	mu      sync.Mutex
	entries map[outboundConsentKey]*outboundConsentEntry
}

type outboundConsentEntry struct {
	token   *ConsentToken
	started bool // a PUT has been attempted under this grant
}

const maxOutboundConsent = 16

func (c *outboundConsentCache) pruneLocked(now time.Time) {
	for k, v := range c.entries {
		if !now.Before(v.token.ExpiresAt) {
			delete(c.entries, k)
		}
	}
}

func (c *outboundConsentCache) store(now time.Time, k outboundConsentKey, tok *ConsentToken) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked(now)
	if !now.Before(tok.ExpiresAt) {
		return
	}
	if c.entries == nil {
		c.entries = make(map[outboundConsentKey]*outboundConsentEntry)
	}
	// Repeated preflight polls must preserve the progress of the same grant.
	if old := c.entries[k]; old != nil && old.token.Nonce == tok.Nonce {
		return
	}
	if len(c.entries) >= maxOutboundConsent {
		var oldest outboundConsentKey
		var expiry time.Time
		for key, entry := range c.entries {
			if expiry.IsZero() || entry.token.ExpiresAt.Before(expiry) {
				oldest, expiry = key, entry.token.ExpiresAt
			}
		}
		delete(c.entries, oldest)
	}
	c.entries[k] = &outboundConsentEntry{token: tok}
}

func (c *outboundConsentCache) load(now time.Time, k outboundConsentKey) *ConsentToken {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked(now)
	if entry := c.entries[k]; entry != nil {
		return entry.token
	}
	return nil
}

// canResume reports whether an earlier PUT used this same grant. A freshly
// approved transaction cannot resume bytes received under a different grant.
func (c *outboundConsentCache) canResume(k outboundConsentKey, tok *ConsentToken) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry := c.entries[k]
	return entry != nil && entry.token.Nonce == tok.Nonce && entry.started
}

func (c *outboundConsentCache) start(k outboundConsentKey, tok *ConsentToken) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if entry := c.entries[k]; entry != nil && entry.token.Nonce == tok.Nonce {
		entry.started = true
	}
}

func (c *outboundConsentCache) Delete(k outboundConsentKey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, k)
}

func (c *outboundConsentCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = nil
}

// gcLocked drops requests and records that are no longer actionable.
func (s *consentStore) gcLocked(now time.Time) {
	for id, g := range s.requests {
		if now.Before(g.expires.Add(consentTerminalTTL)) {
			continue
		}
		if !g.decided && !g.expiryNotified {
			s.expiryChanged = true
		}
		delete(s.requests, id)
	}
	for nonce, rec := range s.records {
		if !rec.InFlight && !now.Before(rec.ExpiresAt.Add(consentTerminalTTL)) {
			delete(s.records, nonce)
		}
	}
}

// consentSecret returns this node's consent HMAC key, generating and persisting
// it on first use.
func (m *manager) consentSecret() ([32]byte, error) {
	s := &m.consent
	s.mu.Lock()
	defer s.mu.Unlock()
	return m.consentSecretLocked()
}

func (m *manager) consentSecretLocked() ([32]byte, error) {
	s := &m.consent
	if s.haveSecret {
		return s.secret, nil
	}
	store := m.opts.State
	if store != nil {
		switch b, err := store.ReadState(ipn.TaildropConsentSecretKey); {
		case err == nil && len(b) == len(s.secret):
			copy(s.secret[:], b)
			s.haveSecret = true
			return s.secret, nil
		case err != nil && err != ipn.ErrStateNotExist:
			return [32]byte{}, err
		}
	}
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return [32]byte{}, err
	}
	if store != nil {
		if err := store.WriteState(ipn.TaildropConsentSecretKey, secret[:]); err != nil {
			return [32]byte{}, err
		}
	}
	s.secret = secret
	s.haveSecret = true
	return secret, nil
}

// consentMessage builds the byte string that a consent token is an HMAC over.
//
// Fields are NULL-separated because neither a StableNodeID nor a filename may
// contain a NULL byte, which makes the encoding unambiguous.
func consentMessage(sender tailcfg.StableNodeID, filename string, expiresAt time.Time, nonce [32]byte, txid, hash string) []byte {
	b := make([]byte, 0, len(sender)+len(filename)+8+8+len(nonce))
	b = append(b, sender...)
	b = append(b, 0)
	b = append(b, filename...)
	b = append(b, 0)
	b = binary.BigEndian.AppendUint64(b, uint64(expiresAt.Unix()))
	b = append(b, nonce[:]...)
	b = append(b, txid...)
	b = append(b, 0)
	return append(b, hash...)
}

func consentMAC(secret [32]byte, sender tailcfg.StableNodeID, filename string, expiresAt time.Time, nonce [32]byte, txid, hash string) []byte {
	mac := hmac.New(sha256.New, secret[:])
	mac.Write(consentMessage(sender, filename, expiresAt, nonce, txid, hash))
	return mac.Sum(nil)
}

// allowExternalTaildrop reports the effective opt-in preference.
func (m *manager) allowExternalTaildrop() bool {
	return m != nil && m.opts.AllowExternalTaildrop != nil && m.opts.AllowExternalTaildrop()
}

// consentForOwnDevices allows one to override the default behavior for self-owned nodes, simplifying
// local testing and development on a single-user tailnet.
func (m *manager) consentForOwnDevices() bool {
	return m.allowExternalTaildrop() && m.opts.ConsentForOwnDevices != nil && m.opts.ConsentForOwnDevices()
}

// requestConsent registers an inbound transfer as awaiting the device owner's
// approval and reports its current state.
//
// It is idempotent for a given (sender, transaction ID): repeated calls report
// the state of the existing request rather than prompting again, so the sender
// may poll. Each file has an independent request and decision.
func (m *manager) requestConsent(sender tailcfg.StableNodeID, senderName, filename string, req PutRequest) (ConsentState, *ConsentToken, error) {
	if err := req.validate(); err != nil {
		return "", nil, err
	}
	size := req.Size
	now := m.opts.Clock.Now()
	s := &m.consent
	s.mu.Lock()
	s.gcLocked(now)
	defer m.wakeConsentExpiry()

	// Match the transaction across all requests, so concurrent sends from the
	// same peer cannot hide each other's decisions.
	for _, g := range s.requests {
		if g.senderID != sender {
			continue
		}
		if f := &g.file; f.txid == req.TxID {
			if f.name != filename || f.size != size || f.hash != req.Hash {
				s.mu.Unlock()
				return "", nil, ErrConsentMismatch
			}
			state, tok := requestStateLocked(g, f)
			if !now.Before(g.expires) {
				state, tok = ConsentDenied, nil
			}
			s.mu.Unlock()
			return state, tok, nil
		}
	}
	var pending, peerPending, peerHistory int
	for _, g := range s.requests {
		if g.senderID == sender {
			peerHistory++
		}
		if !g.decided && now.Before(g.expires) {
			pending++
			if g.senderID == sender {
				peerPending++
			}
		}
	}
	if pending >= maxConsentFiles || peerPending >= maxConsentPeerFiles ||
		len(s.requests) >= maxConsentHistory || peerHistory >= maxConsentPeerHistory || len(s.records) >= maxConsentHistory {
		s.mu.Unlock()
		return "", nil, ErrConsentLimit
	}
	if s.admission == nil {
		s.admission = rate.NewLimiter(16, maxConsentFiles)
	}
	if !s.admission.AllowN(now, 1) {
		s.mu.Unlock()
		return "", nil, ErrConsentLimit
	}
	g := &consentRequest{
		id:         rands.HexString(16),
		senderID:   sender,
		senderName: senderName,
		file:       consentFile{name: filename, size: size, txid: req.TxID, hash: req.Hash},
		requested:  now,
		expires:    now.Add(consentPendingTTL),
	}
	if s.requests == nil {
		s.requests = make(map[string]*consentRequest)
	}
	s.requests[g.id] = g
	s.mu.Unlock()

	m.notifyConsent()
	return ConsentPending, nil, nil
}

func requestStateLocked(g *consentRequest, f *consentFile) (ConsentState, *ConsentToken) {
	switch {
	case !g.decided:
		return ConsentPending, nil
	case !g.allowed || f.used:
		return ConsentDenied, nil
	default:
		return ConsentApproved, f.token
	}
}

// resolveConsent applies the device owner's decision to a pending request.
//
// On approval it mints a token and a consent record for the file.
func (m *manager) resolveConsent(id string, allow bool) error {
	if m == nil {
		return ErrNoTaildrop
	}
	now := m.opts.Clock.Now()
	s := &m.consent
	s.mu.Lock()
	s.gcLocked(now)

	g := s.requests[id]
	if g == nil || !now.Before(g.expires) {
		s.mu.Unlock()
		return ErrConsentUnknown
	}
	if g.decided {
		s.mu.Unlock()
		return ErrConsentConsumed
	}

	g.decided = true
	defer m.wakeConsentExpiry()
	g.allowed = allow

	if allow {
		metricConsentApproved.Add(1)
	} else {
		metricConsentDenied.Add(1)
	}

	if !allow {
		// Keep the request around until it expires so a polling sender learns
		// it was denied rather than timing out.
		s.mu.Unlock()
		m.notifyConsent()
		return nil
	}

	secret, err := m.consentSecretLocked()
	if err != nil {
		g.allowed = false
		s.mu.Unlock()
		m.notifyConsent()
		return err
	}

	expiresAt := now.Add(consentTokenTTL).Truncate(time.Second)
	if g.expires.Before(expiresAt) {
		g.expires = expiresAt
	}
	if s.records == nil {
		s.records = make(map[[32]byte]*consentRecord)
	}
	f := &g.file
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		g.allowed = false
		s.mu.Unlock()
		m.notifyConsent()
		return err
	}
	mac := consentMAC(secret, g.senderID, f.name, expiresAt, nonce, f.txid, f.hash)
	f.token = &ConsentToken{
		TxID: f.txid, Hash: f.hash,
		Token:     base64.RawURLEncoding.EncodeToString(mac),
		Nonce:     base64.RawURLEncoding.EncodeToString(nonce[:]),
		ExpiresAt: expiresAt,
	}
	s.records[nonce] = &consentRecord{
		TxID: f.txid, Hash: f.hash,
		SenderID:  g.senderID,
		Filename:  f.name,
		Size:      f.size,
		Nonce:     nonce,
		ExpiresAt: expiresAt,
	}
	s.mu.Unlock()

	m.notifyConsent()
	return nil
}

// pendingConsentRequests returns the requests still awaiting a decision, oldest
// first.
//
// The result is always non-nil, so an empty result tells a client there is
// nothing outstanding rather than telling it nothing at all.
func (m *manager) pendingConsentRequests() []taildroptype.ConsentRequest {
	out := make([]taildroptype.ConsentRequest, 0)
	if m == nil {
		return out
	}
	now := m.opts.Clock.Now()
	s := &m.consent
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, g := range s.requests {
		if g.decided || !now.Before(g.expires) {
			continue
		}
		out = append(out, g.asNotify())
	}
	slices.SortFunc(out, func(a, b taildroptype.ConsentRequest) int {
		if c := a.Requested.Compare(b.Requested); c != 0 {
			return c
		}
		return cmpString(a.RequestID, b.RequestID)
	})
	return out
}

func cmpString(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func (m *manager) notifyConsent() {
	if m != nil && m.opts.NotifyConsent != nil {
		m.opts.NotifyConsent()
	}
}

func (m *manager) wakeConsentExpiry() {
	m.consentStartOnce.Do(func() { go m.runConsentExpiry() })
	select {
	case m.consentWake <- struct{}{}:
	default:
	}
}

// runConsentExpiry owns the timer and exits before manager.Shutdown returns.
// Reads filter expired entries immediately; this worker also dismisses prompts
// and eventually frees terminal records without needing another HTTP request.
func (m *manager) runConsentExpiry() {
	defer close(m.consentDone)
	for {
		now := m.opts.Clock.Now()
		s := &m.consent
		s.mu.Lock()
		s.gcLocked(now)
		var next time.Time
		changed := s.expiryChanged
		s.expiryChanged = false
		for _, g := range s.requests {
			if !g.decided && !g.expiryNotified && !now.Before(g.expires) {
				g.expiryNotified = true
				changed = true
			}
			deadline := g.expires.Add(consentTerminalTTL)
			if !g.decided && !g.expiryNotified {
				deadline = g.expires
			}
			if next.IsZero() || deadline.Before(next) {
				next = deadline
			}
		}
		for _, rec := range s.records {
			deadline := rec.ExpiresAt.Add(consentTerminalTTL)
			if !rec.InFlight && (next.IsZero() || deadline.Before(next)) {
				next = deadline
			}
		}
		s.mu.Unlock()
		if changed {
			m.notifyConsent()
		}
		var timerChan <-chan time.Time
		var stop func()
		if !next.IsZero() {
			timer, ch := m.opts.Clock.NewTimer(max(0, next.Sub(m.opts.Clock.Now())))
			timerChan = ch
			stop = func() { timer.Stop() }
		}
		select {
		case <-m.consentStop:
			if stop != nil {
				stop()
			}
			return
		case <-m.consentWake:
		case <-timerChan:
		}
		if stop != nil {
			stop()
		}
	}
}

// beginConsentedPut authorizes one consented PUT and marks its consent record
// in use. The caller must pair every nil-error return with exactly one
// [manager.endConsentedPut] for the returned nonce.
//
// It performs every check before the caller reads any request body, so an
// unauthorized sender never gets to write a byte to disk.
func (m *manager) beginConsentedPut(sender tailcfg.StableNodeID, filename string, hdr http.Header, offset, contentLength int64) (nonce [32]byte, err error) {
	rawToken := hdr.Get(hdrConsentToken)
	rawNonce := hdr.Get(hdrConsentNonce)
	rawExpires := hdr.Get(hdrConsentExpires)
	if rawToken == "" && rawNonce == "" && rawExpires == "" {
		return nonce, ErrConsentRequired
	}

	hdrExpires, err := time.Parse(time.RFC3339, rawExpires)
	if err != nil {
		return nonce, ErrConsentMalformed
	}
	nonceBytes, err := base64.RawURLEncoding.DecodeString(rawNonce)
	if err != nil || len(nonceBytes) != len(nonce) {
		return nonce, ErrConsentMalformed
	}
	copy(nonce[:], nonceBytes)
	token, err := base64.RawURLEncoding.DecodeString(rawToken)
	if err != nil || len(token) != sha256.Size {
		return nonce, ErrConsentMalformed
	}

	// A consented transfer must declare its length: the token is bound to a
	// specific size, and we can't check a size we weren't told.
	if contentLength < 0 {
		return nonce, ErrConsentMismatch
	}

	now := m.opts.Clock.Now()
	s := &m.consent
	s.mu.Lock()
	defer s.mu.Unlock()

	rec := s.records[nonce]
	switch {
	case rec == nil:
		return nonce, ErrConsentUnknown
	case rec.Consumed || rec.InFlight:
		return nonce, ErrConsentConsumed
	case !now.Before(rec.ExpiresAt):
		return nonce, ErrConsentExpired
	case rec.SenderID != sender || rec.Filename != filename || rec.TxID != hdr.Get(hdrConsentTxID):
		return nonce, ErrConsentMismatch
	case offset+contentLength != rec.Size || offset > rec.BytesReceived:
		return nonce, ErrConsentMismatch
	case !hdrExpires.Equal(rec.ExpiresAt):
		// The record's expiry is authoritative; the header only has to agree
		// with it, since it is one of the fields the token commits to.
		return nonce, ErrConsentMismatch
	}

	secret, err := m.consentSecretLocked()
	if err != nil {
		return nonce, err
	}
	want := consentMAC(secret, rec.SenderID, rec.Filename, rec.ExpiresAt, nonce, rec.TxID, rec.Hash)
	if !hmac.Equal(token, want) {
		return nonce, ErrConsentInvalid
	}

	rec.InFlight = true
	return nonce, nil
}

// endConsentedPut releases the consent record for nonce.
//
// Completion or a hash mismatch consumes the record. An interrupted transfer
// records its received prefix and leaves the grant available for a retry.
func (m *manager) endConsentedPut(nonce [32]byte, fileLength int64, transferErr error) {
	defer m.wakeConsentExpiry()
	s := &m.consent
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := s.records[nonce]
	if rec == nil {
		return
	}
	rec.InFlight = false
	if fileLength > rec.BytesReceived {
		rec.BytesReceived = fileLength
	}
	if transferErr == ErrConsentHashMismatch || (transferErr == nil && rec.BytesReceived >= rec.Size) {
		rec.Consumed = true
		for _, g := range s.requests {
			if g.senderID == rec.SenderID {
				if f := &g.file; f.txid == rec.TxID {
					f.used = true
				}
			}
		}
	}
}
