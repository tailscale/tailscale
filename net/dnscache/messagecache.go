// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package dnscache

import (
	"cmp"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/golang/groupcache/lru"
	"golang.org/x/net/dns/dnsmessage"
)

// MessageCache is a cache that works at the DNS message layer,
// with its cache keyed on a DNS wire-level question, and capable
// of replying to DNS messages.
//
// Its zero value is ready for use with a default cache size.
// Use SetMaxCacheSize to specify the cache size.
//
// It's safe for concurrent use.
type MessageCache struct {
	// Clock is a clock, for testing.
	// If nil, time.Now is used.
	Clock func() time.Time

	mu           sync.Mutex
	cacheSizeSet int       // 0 means default
	cache        lru.Cache // msgQ => *msgCacheValue
}

func (c *MessageCache) now() time.Time {
	if c.Clock != nil {
		return c.Clock()
	}
	return time.Now()
}

// SetMaxCacheSize sets the maximum number of DNS cache entries that
// can be stored.
func (c *MessageCache) SetMaxCacheSize(n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cacheSizeSet = n
	c.pruneLocked()
}

// Flush clears the cache.
func (c *MessageCache) Flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache.Clear()
}

// pruneLocked prunes down the cache size to the configured (or
// default) max size.
func (c *MessageCache) pruneLocked() {
	max := cmp.Or(c.cacheSizeSet, 500)
	for c.cache.Len() > max {
		c.cache.RemoveOldest()
	}
}

// msgQ is the MessageCache cache key.
//
// It's basically a golang.org/x/net/dns/dnsmessage#Question but the
// Class is omitted (we only cache ClassINET) and we store a Go string
// instead of a 256 byte dnsmessage.Name array.
type msgQ struct {
	Name string
	Type dnsmessage.Type // A, AAAA, MX, etc
}

// A *msgCacheValue is the cached value for a msgQ (question) key.
//
// Despite using pointers for storage and methods, the value is
// immutable once placed in the cache.
type msgCacheValue struct {
	Expires time.Time

	// Answers are the minimum data to reconstruct a DNS response
	// message. TTLs are added later when converting to a
	// dnsmessage.Resource.
	Answers []msgResource
}

type msgResource struct {
	Name string
	Type dnsmessage.Type // dnsmessage.UnknownResource.Type
	Data []byte          // dnsmessage.UnknownResource.Data
}

// ErrCacheMiss is a sentinel error returned by MessageCache.ReplyFromCache
// when the request can not be satisfied from cache.
var ErrCacheMiss = errors.New("cache miss")

var parserPool = &sync.Pool{
	New: func() any { return new(dnsmessage.Parser) },
}

// ReplyFromCache writes a DNS reply to w for the provided DNS query message,
// which must begin with the two ID bytes of a DNS message.
//
// If there's a cache miss, the message is invalid or unexpected,
// ErrCacheMiss is returned. On cache hit, either nil or an error from
// a w.Write call is returned.
func (c *MessageCache) ReplyFromCache(w io.Writer, dnsQueryMessage []byte) error {
	cacheKey, txID, ok := getDNSQueryCacheKey(dnsQueryMessage)
	if !ok {
		return ErrCacheMiss
	}
	now := c.now()

	c.mu.Lock()
	cacheEntI, _ := c.cache.Get(cacheKey)
	v, ok := cacheEntI.(*msgCacheValue)
	if ok && now.After(v.Expires) {
		c.cache.Remove(cacheKey)
		ok = false
	}
	c.mu.Unlock()

	if !ok {
		return ErrCacheMiss
	}

	ttl := uint32(v.Expires.Sub(now).Seconds())

	packedRes, err := packDNSResponse(cacheKey, txID, ttl, v.Answers)
	if err != nil {
		return ErrCacheMiss
	}
	_, err = w.Write(packedRes)
	return err
}

var (
	errNotCacheable = errors.New("question not cacheable")
)

// AddCacheEntry adds a cache entry to the cache.
// It returns an error if the entry could not be cached.
func (c *MessageCache) AddCacheEntry(qPacket, res []byte) error {
	cacheKey, qID, ok := getDNSQueryCacheKey(qPacket)
	if !ok {
		return errNotCacheable
	}
	now := c.now()
	v := &msgCacheValue{}

	p := parserPool.Get().(*dnsmessage.Parser)
	defer parserPool.Put(p)

	resh, err := p.Start(res)
	if err != nil {
		return fmt.Errorf("reading header in response: %w", err)
	}
	if resh.ID != qID {
		return fmt.Errorf("response ID doesn't match query ID")
	}
	q, err := p.Question()
	if err != nil {
		return fmt.Errorf("reading 1st question in response: %w", err)
	}
	if _, err := p.Question(); err != dnsmessage.ErrSectionDone {
		if err == nil {
			return errors.New("unexpected 2nd question in response")
		}
		return fmt.Errorf("after reading 1st question in response: %w", err)
	}
	if resName := asciiLowerName(q.Name).String(); resName != cacheKey.Name {
		return fmt.Errorf("response question name %q != question name %q", resName, cacheKey.Name)
	}
	for {
		rh, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return fmt.Errorf("reading answer: %w", err)
		}
		res, err := p.UnknownResource()
		if err != nil {
			return fmt.Errorf("reading resource: %w", err)
		}
		if rh.Class != dnsmessage.ClassINET {
			continue
		}

		// Set the cache entry's expiration to the soonest
		// we've seen. (They should all be the same, though)
		expires := now.Add(time.Duration(rh.TTL) * time.Second)
		if v.Expires.IsZero() || expires.Before(v.Expires) {
			v.Expires = expires
		}
		v.Answers = append(v.Answers, msgResource{
			Name: rh.Name.String(),
			Type: rh.Type,
			Data: res.Data, // doesn't alias; a copy from dnsmessage.unpackUnknownResource
		})
	}
	c.addCacheValue(cacheKey, v)
	return nil
}

func (c *MessageCache) addCacheValue(cacheKey msgQ, v *msgCacheValue) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache.Add(cacheKey, v)
	c.pruneLocked()
}

func getDNSQueryCacheKey(msg []byte) (cacheKey msgQ, txID uint16, ok bool) {
	p := parserPool.Get().(*dnsmessage.Parser)
	defer parserPool.Put(p)
	h, err := p.Start(msg)
	const dnsHeaderSize = 12
	if err != nil || h.OpCode != 0 || h.Response || h.Truncated ||
		len(msg) < dnsHeaderSize { // p.Start checks this anyway, but to be explicit for slicing below
		return cacheKey, 0, false
	}
	var (
		numQ    = binary.BigEndian.Uint16(msg[4:6])
		numAns  = binary.BigEndian.Uint16(msg[6:8])
		numAuth = binary.BigEndian.Uint16(msg[8:10])
		numAddn = binary.BigEndian.Uint16(msg[10:12])
	)
	_ = numAddn // ignore this for now; do client OSes send EDNS additional? assume so, ignore.
	if !(numQ == 1 && numAns == 0 && numAuth == 0) {
		// Something weird. We don't want to deal with it.
		return cacheKey, 0, false
	}
	q, err := p.Question()
	if err != nil {
		// Already verified numQ == 1 so shouldn't happen, but:
		return cacheKey, 0, false
	}
	if q.Class != dnsmessage.ClassINET {
		// We only cache the Internet class.
		return cacheKey, 0, false
	}
	return msgQ{Name: asciiLowerName(q.Name).String(), Type: q.Type}, h.ID, true
}

func asciiLowerName(n dnsmessage.Name) dnsmessage.Name {
	nb := n.Data[:]
	if int(n.Length) < len(n.Data) {
		nb = nb[:n.Length]
	}
	for i, b := range nb {
		if 'A' <= b && b <= 'Z' {
			n.Data[i] += 0x20
		}
	}
	return n
}

// packDNSResponse builds a DNS response for the given question and
// transaction ID. The response resource records will have the
// same provided TTL.
func packDNSResponse(q msgQ, txID uint16, ttl uint32, answers []msgResource) ([]byte, error) {
	var baseMem []byte // TODO: guess a max size based on looping over answers?
	b := dnsmessage.NewBuilder(baseMem, dnsmessage.Header{
		ID:            txID,
		Response:      true,
		OpCode:        0,
		Authoritative: false,
		Truncated:     false,
		RCode:         dnsmessage.RCodeSuccess,
	})
	name, err := dnsmessage.NewName(q.Name)
	if err != nil {
		return nil, err
	}
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(dnsmessage.Question{
		Name:  name,
		Type:  q.Type,
		Class: dnsmessage.ClassINET,
	}); err != nil {
		return nil, err
	}
	if err := b.StartAnswers(); err != nil {
		return nil, err
	}
	for _, r := range answers {
		name, err := dnsmessage.NewName(r.Name)
		if err != nil {
			return nil, err
		}
		if err := b.UnknownResource(dnsmessage.ResourceHeader{
			Name:  name,
			Type:  r.Type,
			Class: dnsmessage.ClassINET,
			TTL:   ttl,
		}, dnsmessage.UnknownResource{
			Type: r.Type,
			Data: r.Data,
		}); err != nil {
			return nil, err
		}
	}
	return b.Finish()
}
