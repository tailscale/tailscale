// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tsdns provides a Resolver capable of resolving
// domains on a Tailscale network.
package tsdns

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"time"

	dns "golang.org/x/net/dns/dnsmessage"
	"inet.af/netaddr"
	"tailscale.com/net/netns"
	"tailscale.com/types/logger"
)

// maxResponseSize is the maximum size of a response from a Resolver.
const maxResponseSize = 512

// queueSize is the maximal number of DNS requests that can be pending at a time.
// If EnqueueRequest is called when this many requests are already pending,
// the request will be dropped to avoid blocking the caller.
const queueSize = 8

// delegateTimeout is the maximal amount of time Resolver will wait
// for upstream nameservers to process a query.
const delegateTimeout = 5 * time.Second

// defaultTTL is the TTL of all responses from Resolver.
const defaultTTL = 600 * time.Second

// ErrClosed indicates that the resolver has been closed and readers should exit.
var ErrClosed = errors.New("closed")

var (
	errAllFailed      = errors.New("all upstream nameservers failed")
	errFullQueue      = errors.New("request queue full")
	errMapNotSet      = errors.New("domain map not set")
	errNotImplemented = errors.New("query type not implemented")
	errNotQuery       = errors.New("not a DNS query")
)

// Map is all the data Resolver needs to resolve DNS queries within the Tailscale network.
type Map struct {
	// domainToIP is a mapping of Tailscale domains to their IP addresses.
	// For example, monitoring.tailscale.us -> 100.64.0.1.
	domainToIP map[string]netaddr.IP
}

// NewMap returns a new Map with domain to address mapping given by domainToIP.
func NewMap(domainToIP map[string]netaddr.IP) *Map {
	return &Map{domainToIP: domainToIP}
}

// Packet represents a DNS payload together with the address of its origin.
type Packet struct {
	// Payload is the application layer DNS payload.
	// Resolver assumes ownership of the request payload when it is enqueued
	// and cedes ownership of the response payload when it is returned from NextResponse.
	Payload []byte
	// Addr is the source address for a request and the destination address for a response.
	Addr netaddr.IPPort
}

// Resolver is a DNS resolver for nodes on the Tailscale network,
// associating them with domain names of the form <mynode>.<mydomain>.<root>.
// If it is asked to resolve a domain that is not of that form,
// it delegates to upstream nameservers if any are set.
type Resolver struct {
	logf logger.Logf

	// The asynchronous interface is due to the fact that resolution may potentially
	// block for a long time (if the upstream nameserver is slow to reach).

	// queue is a buffered channel holding DNS requests queued for resolution.
	queue chan Packet
	// responses is an unbuffered channel to which responses are sent.
	responses chan Packet
	// errors is an unbuffered channel to which errors are sent.
	errors chan error
	// closed notifies the poll goroutines to stop.
	closed chan struct{}
	// pollGroup signals when all poll goroutines have stopped.
	pollGroup sync.WaitGroup

	// rootDomain is <root> in <mynode>.<mydomain>.<root>.
	rootDomain []byte

	// dialer is the netns.Dialer used for delegation.
	dialer netns.Dialer

	// mu guards the following fields from being updated while used.
	mu sync.RWMutex
	// dnsMap is the map most recently received from the control server.
	dnsMap *Map
	// nameservers is the list of nameserver addresses that should be used
	// if the received query is not for a Tailscale node.
	// The addresses are strings of the form ip:port, as expected by Dial.
	nameservers []string
}

// NewResolver constructs a resolver associated with the given root domain.
func NewResolver(logf logger.Logf, rootDomain string) *Resolver {
	r := &Resolver{
		logf:      logger.WithPrefix(logf, "tsdns: "),
		queue:     make(chan Packet, queueSize),
		responses: make(chan Packet),
		errors:    make(chan error),
		closed:    make(chan struct{}),
		// Conform to the name format dnsmessage uses (trailing period, bytes).
		rootDomain: []byte(rootDomain + "."),
		dialer:     netns.NewDialer(),
	}

	return r
}

func (r *Resolver) Start() {
	// TODO(dmytro): spawn more than one goroutine? They block on delegation.
	r.pollGroup.Add(1)
	go r.poll()
}

// Close shuts down the resolver and ensures poll goroutines have exited.
// The Resolver cannot be used again after Close is called.
func (r *Resolver) Close() {
	select {
	case <-r.closed:
		return
	default:
		// continue
	}
	close(r.closed)
	r.pollGroup.Wait()
}

// SetMap sets the resolver's DNS map, taking ownership of it.
func (r *Resolver) SetMap(m *Map) {
	r.mu.Lock()
	r.dnsMap = m
	r.mu.Unlock()
}

// SetUpstreamNameservers sets the addresses of the resolver's
// upstream nameservers, taking ownership of the argument.
// The addresses should be strings of the form ip:port,
// matching what Dial("udp", addr) expects as addr.
func (r *Resolver) SetNameservers(nameservers []string) {
	r.mu.Lock()
	r.nameservers = nameservers
	r.mu.Unlock()
}

// EnqueueRequest places the given DNS request in the resolver's queue.
// It takes ownership of the payload and does not block.
// If the queue is full, the request will be dropped and an error will be returned.
func (r *Resolver) EnqueueRequest(request Packet) error {
	select {
	case r.queue <- request:
		return nil
	default:
		return errFullQueue
	}
}

// NextResponse returns a DNS response to a previously enqueued request.
// It blocks until a response is available and gives up ownership of the response payload.
func (r *Resolver) NextResponse() (Packet, error) {
	select {
	case resp := <-r.responses:
		return resp, nil
	case err := <-r.errors:
		return Packet{}, err
	case <-r.closed:
		return Packet{}, ErrClosed
	}
}

// Resolve maps a given domain name to the IP address of the host that owns it.
// The domain name must not have a trailing period.
func (r *Resolver) Resolve(domain string) (netaddr.IP, dns.RCode, error) {
	r.mu.RLock()
	if r.dnsMap == nil {
		r.mu.RUnlock()
		return netaddr.IP{}, dns.RCodeServerFailure, errMapNotSet
	}
	addr, found := r.dnsMap.domainToIP[domain]
	r.mu.RUnlock()

	if !found {
		return netaddr.IP{}, dns.RCodeNameError, nil
	}
	return addr, dns.RCodeSuccess, nil
}

func (r *Resolver) poll() {
	defer r.pollGroup.Done()

	var (
		packet Packet
		err    error
	)
	for {
		select {
		case packet = <-r.queue:
			// continue
		case <-r.closed:
			return
		}

		packet.Payload, err = r.respond(packet.Payload)
		if err != nil {
			select {
			case r.errors <- err:
				// continue
			case <-r.closed:
				return
			}
		} else {
			select {
			case r.responses <- packet:
				// continue
			case <-r.closed:
				return
			}
		}
	}
}

// queryServer obtains a DNS response by querying the given server.
func (r *Resolver) queryServer(ctx context.Context, server string, query []byte) ([]byte, error) {
	conn, err := r.dialer.DialContext(ctx, "udp", server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Interrupt the current operation when the context is cancelled.
	go func() {
		<-ctx.Done()
		conn.SetDeadline(time.Unix(1, 0))
	}()

	_, err = conn.Write(query)
	if err != nil {
		return nil, err
	}

	out := make([]byte, maxResponseSize)
	n, err := conn.Read(out)
	if err != nil {
		return nil, err
	}

	return out[:n], nil
}

// delegate forwards the query to all upstream nameservers and returns the first response.
func (r *Resolver) delegate(query []byte) ([]byte, error) {
	r.mu.RLock()
	nameservers := r.nameservers
	r.mu.RUnlock()

	if len(nameservers) == 0 {
		return nil, errAllFailed
	}

	ctx, cancel := context.WithTimeout(context.Background(), delegateTimeout)
	defer cancel()

	// Common case, don't spawn goroutines.
	if len(nameservers) == 1 {
		return r.queryServer(ctx, nameservers[0], query)
	}

	datach := make(chan []byte)
	for _, server := range nameservers {
		go func(s string) {
			resp, err := r.queryServer(ctx, s, query)
			// Only print errors not due to cancelation after first response.
			if err != nil && ctx.Err() != context.Canceled {
				r.logf("querying %s: %v", s, err)
			}

			datach <- resp
		}(server)
	}

	var response []byte
	for range nameservers {
		cur := <-datach
		if cur != nil && response == nil {
			// Received first successful response
			response = cur
			cancel()
		}
	}

	if response == nil {
		return nil, errAllFailed
	}
	return response, nil
}

type response struct {
	Header   dns.Header
	Question dns.Question
	Name     string
	IP       netaddr.IP
}

// parseQuery parses the query in given packet into a response struct.
func (r *Resolver) parseQuery(query []byte, resp *response) error {
	var parser dns.Parser
	var err error

	resp.Header, err = parser.Start(query)
	if err != nil {
		return err
	}

	if resp.Header.Response {
		return errNotQuery
	}

	resp.Question, err = parser.Question()
	if err != nil {
		return err
	}

	return nil
}

// marshalARecord serializes an A record into an active builder.
// The caller may continue using the builder following the call.
func marshalARecord(name dns.Name, ip netaddr.IP, builder *dns.Builder) error {
	var answer dns.AResource

	answerHeader := dns.ResourceHeader{
		Name:  name,
		Type:  dns.TypeA,
		Class: dns.ClassINET,
		TTL:   uint32(defaultTTL / time.Second),
	}
	ipbytes := ip.As4()
	copy(answer.A[:], ipbytes[:])
	return builder.AResource(answerHeader, answer)
}

// marshalAAAARecord serializes an AAAA record into an active builder.
// The caller may continue using the builder following the call.
func marshalAAAARecord(name dns.Name, ip netaddr.IP, builder *dns.Builder) error {
	var answer dns.AAAAResource

	answerHeader := dns.ResourceHeader{
		Name:  name,
		Type:  dns.TypeAAAA,
		Class: dns.ClassINET,
		TTL:   uint32(defaultTTL / time.Second),
	}
	ipbytes := ip.As16()
	copy(answer.AAAA[:], ipbytes[:])
	return builder.AAAAResource(answerHeader, answer)
}

// marshalResponse serializes the DNS response into a new buffer.
func marshalResponse(resp *response) ([]byte, error) {
	resp.Header.Response = true
	resp.Header.Authoritative = true
	if resp.Header.RecursionDesired {
		resp.Header.RecursionAvailable = true
	}

	builder := dns.NewBuilder(nil, resp.Header)

	err := builder.StartQuestions()
	if err != nil {
		return nil, err
	}

	err = builder.Question(resp.Question)
	if err != nil {
		return nil, err
	}

	// Only successful responses contain answers.
	if resp.Header.RCode != dns.RCodeSuccess {
		return builder.Finish()
	}

	err = builder.StartAnswers()
	if err != nil {
		return nil, err
	}

	if resp.IP.Is4() {
		err = marshalARecord(resp.Question.Name, resp.IP, &builder)
	} else {
		err = marshalAAAARecord(resp.Question.Name, resp.IP, &builder)
	}
	if err != nil {
		return nil, err
	}

	return builder.Finish()
}

// respond returns a DNS response to query.
func (r *Resolver) respond(query []byte) ([]byte, error) {
	resp := new(response)

	// ParseQuery is sufficiently fast to run on every DNS packet.
	// This is considerably simpler than extracting the name by hand
	// to shave off microseconds in case of delegation.
	err := r.parseQuery(query, resp)
	// We will not return this error: it is the sender's fault.
	if err != nil {
		r.logf("parsing query: %v", err)
		resp.Header.RCode = dns.RCodeFormatError
		return marshalResponse(resp)
	}

	// Delegate only when not a subdomain of rootDomain.
	// We do this on bytes because Name.String() allocates.
	rawName := resp.Question.Name.Data[:resp.Question.Name.Length]
	if !bytes.HasSuffix(rawName, r.rootDomain) {
		out, err := r.delegate(query)
		if err != nil {
			r.logf("delegating: %v", err)
			resp.Header.RCode = dns.RCodeServerFailure
			return marshalResponse(resp)
		}
		return out, nil
	}

	switch resp.Question.Type {
	case dns.TypeA, dns.TypeAAAA, dns.TypeALL:
		domain := resp.Question.Name.String()
		// Strip off the trailing period.
		// This is safe: Name is guaranteed to have a trailing period by construction.
		domain = domain[:len(domain)-1]
		resp.IP, resp.Header.RCode, err = r.Resolve(domain)
	default:
		resp.Header.RCode = dns.RCodeNotImplemented
		err = errNotImplemented
	}
	// We will not return this error: it is the sender's fault.
	if err != nil {
		r.logf("resolving: %v", err)
	}

	return marshalResponse(resp)
}
