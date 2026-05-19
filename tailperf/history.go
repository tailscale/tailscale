// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailperf

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
)

type HistoryStore struct {
	Path             string
	RetentionRecords int
}

func (s HistoryStore) Append(ctx context.Context, r Result) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.Path == "" {
		return fmt.Errorf("tailperf history path is empty")
	}
	f, err := os.OpenFile(s.Path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		return err
	}
	return s.Prune(ctx)
}

func (s HistoryStore) Load(ctx context.Context) ([]Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.Path == "" {
		return nil, fmt.Errorf("tailperf history path is empty")
	}
	f, err := os.Open(s.Path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Result
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var r Result
		if err := json.Unmarshal(line, &r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s HistoryStore) Prune(ctx context.Context) error {
	if s.RetentionRecords <= 0 {
		return nil
	}
	rs, err := s.Load(ctx)
	if err != nil {
		return err
	}
	if len(rs) <= s.RetentionRecords {
		return nil
	}
	rs = rs[len(rs)-s.RetentionRecords:]
	var buf bytes.Buffer
	for _, r := range rs {
		b, err := json.Marshal(r)
		if err != nil {
			return err
		}
		buf.Write(b)
		buf.WriteByte('\n')
	}
	return os.WriteFile(s.Path, buf.Bytes(), 0600)
}

func (s HistoryStore) ExportSupport(ctx context.Context, opts RedactionOptions) ([]byte, error) {
	rs, err := s.Load(ctx)
	if err != nil {
		return nil, err
	}
	for i := range rs {
		rs[i] = RedactResult(rs[i], opts)
	}
	return json.MarshalIndent(rs, "", "  ")
}

func RedactResult(r Result, opts RedactionOptions) Result {
	if opts.HideNodeNames {
		if r.SourceNode != "" {
			r.SourceNode = "redacted-source"
		}
		if r.DestinationNode != "" {
			r.DestinationNode = "redacted-destination"
		}
	}
	r.Path = redactPath(r.Path, opts)
	for i := range r.Intervals {
		r.Intervals[i].Path = redactPath(r.Intervals[i].Path, opts)
	}
	for i := range r.PathChanges {
		r.PathChanges[i].From = redactPath(r.PathChanges[i].From, opts)
		r.PathChanges[i].To = redactPath(r.PathChanges[i].To, opts)
	}
	r.Redacted = true
	return r
}

func redactPath(p PathMetadata, opts RedactionOptions) PathMetadata {
	if opts.HideRelayNames {
		p.DERPRegionCode = ""
		p.DERPRegionName = ""
		p.PeerRelay = ""
	}
	if opts.HidePrivateIPs || opts.HidePublicIPs {
		if redactAddrPort(p.Endpoint, opts) {
			p.Endpoint = "redacted"
		}
		if redactAddrPort(p.PeerRelay, opts) {
			p.PeerRelay = "redacted"
		}
	}
	return p
}

func redactAddrPort(s string, opts RedactionOptions) bool {
	if s == "" {
		return false
	}
	host := s
	if h, _, err := net.SplitHostPort(s); err == nil {
		host = h
	}
	ip, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return false
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.Is6() && ip.IsPrivate() {
		return opts.HidePrivateIPs
	}
	return opts.HidePublicIPs
}
