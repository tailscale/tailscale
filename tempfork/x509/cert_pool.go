// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"encoding/pem"
	"errors"
	"runtime"
)

// CertPool is a set of certificates.
type CertPool struct {
	bySubjectKeyId map[string][]int // cert.SubjectKeyId => getCert index
	byName         map[string][]int // cert.RawSubject => getCert index

	// getCert contains funcs that return the certificates.
	getCert []func() (*Certificate, error)

	// rawSubjects is each cert's RawSubject field.
	// Its indexes correspond to the getCert indexes.
	rawSubjects [][]byte
}

// NewCertPool returns a new, empty CertPool.
func NewCertPool() *CertPool {
	return &CertPool{
		bySubjectKeyId: make(map[string][]int),
		byName:         make(map[string][]int),
	}
}

// len returns the number of certs in the set.
// A nil set is a valid empty set.
func (s *CertPool) len() int {
	if s == nil {
		return 0
	}
	return len(s.getCert)
}

// cert returns cert index n in s.
func (s *CertPool) cert(n int) (*Certificate, error) {
	return s.getCert[n]()
}

func (s *CertPool) copy() *CertPool {
	p := &CertPool{
		bySubjectKeyId: make(map[string][]int, len(s.bySubjectKeyId)),
		byName:         make(map[string][]int, len(s.byName)),
		getCert:        make([]func() (*Certificate, error), len(s.getCert)),
		rawSubjects:    make([][]byte, len(s.rawSubjects)),
	}
	for k, v := range s.bySubjectKeyId {
		indexes := make([]int, len(v))
		copy(indexes, v)
		p.bySubjectKeyId[k] = indexes
	}
	for k, v := range s.byName {
		indexes := make([]int, len(v))
		copy(indexes, v)
		p.byName[k] = indexes
	}
	copy(p.getCert, s.getCert)
	copy(p.rawSubjects, s.rawSubjects)
	return p
}

// SystemCertPool returns a copy of the system cert pool.
//
// Any mutations to the returned pool are not written to disk and do
// not affect any other pool returned by SystemCertPool.
//
// New changes in the system cert pool might not be reflected
// in subsequent calls.
func SystemCertPool() (*CertPool, error) {
	if runtime.GOOS == "windows" {
		// Issue 16736, 18609:
		return nil, errors.New("crypto/x509: system root pool is not available on Windows")
	}

	if sysRoots := systemRootsPool(); sysRoots != nil {
		return sysRoots.copy(), nil
	}

	return loadSystemRoots()
}

// findPotentialParents returns the indexes of certificates in s which might
// have signed cert. The caller must not modify the returned slice.
func (s *CertPool) findPotentialParents(cert *Certificate) []int {
	if s == nil {
		return nil
	}

	var candidates []int
	if len(cert.AuthorityKeyId) > 0 {
		candidates = s.bySubjectKeyId[string(cert.AuthorityKeyId)]
	}
	if len(candidates) == 0 {
		candidates = s.byName[string(cert.RawIssuer)]
	}
	return candidates
}

func (s *CertPool) contains(cert *Certificate) (bool, error) {
	if s == nil {
		return false, nil
	}
	candidates := s.byName[string(cert.RawSubject)]
	for _, i := range candidates {
		c, err := s.cert(i)
		if err != nil {
			return false, err
		}
		if c.Equal(cert) {
			return true, nil
		}
	}

	return false, nil
}

// AddCert adds a certificate to a pool.
func (s *CertPool) AddCert(cert *Certificate) {
	if cert == nil {
		panic("adding nil Certificate to CertPool")
	}
	err := s.AddCertFunc(string(cert.RawSubject), string(cert.SubjectKeyId), func() (*Certificate, error) {
		return cert, nil
	})
	if err != nil {
		panic(err.Error())
	}
}

// AddCertFunc adds metadata about a certificate to a pool, along with
// a func to fetch that certificate later when needed.
//
// The rawSubject is Certificate.RawSubject and must be non-empty.
// The subjectKeyID is Certificate.SubjectKeyId and may be empty.
// The getCert func may be called 0 or more times.
func (s *CertPool) AddCertFunc(rawSubject, subjectKeyID string, getCert func() (*Certificate, error)) error {
	if getCert == nil {
		panic("getCert can't be nil")
	}

	// Check that the certificate isn't being added twice.
	if len(s.byName[rawSubject]) > 0 {
		c, err := getCert()
		if err != nil {
			return err
		}
		if dup, err := s.contains(c); dup {
			return nil
		} else if err != nil {
			return err
		}
	}

	n := len(s.getCert)
	s.getCert = append(s.getCert, getCert)

	if subjectKeyID != "" {
		s.bySubjectKeyId[subjectKeyID] = append(s.bySubjectKeyId[subjectKeyID], n)
	}
	s.byName[rawSubject] = append(s.byName[rawSubject], n)
	s.rawSubjects = append(s.rawSubjects, []byte(rawSubject))
	return nil
}

// AppendCertsFromPEM attempts to parse a series of PEM encoded certificates.
// It appends any certificates found to s and reports whether any certificates
// were successfully parsed.
//
// On many Linux systems, /etc/ssl/cert.pem will contain the system wide set
// of root CAs in a format suitable for this function.
func (s *CertPool) AppendCertsFromPEM(pemCerts []byte) (ok bool) {
	for len(pemCerts) > 0 {
		var block *pem.Block
		block, pemCerts = pem.Decode(pemCerts)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}

		cert, err := ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}

		s.AddCert(cert)
		ok = true
	}

	return
}

// Subjects returns a list of the DER-encoded subjects of
// all of the certificates in the pool.
func (s *CertPool) Subjects() [][]byte {
	res := make([][]byte, s.len())
	for i, s := range s.rawSubjects {
		res[i] = s
	}
	return res
}
