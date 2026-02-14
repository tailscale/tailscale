package resolver

import (
	"errors"

	"golang.org/x/net/dns/dnsmessage"
)

// extractOPTResource parses a DNS message and returns the OPT resource if present.
func extractOPTResource(msg []byte) *dnsmessage.Resource {
	var p dnsmessage.Parser
	if _, err := p.Start(msg); err != nil {
		return nil
	}

	var optRes *dnsmessage.Resource
	optRes = nil

	// Fast-forward to find OPT
	if err := p.SkipAllQuestions(); err == nil {
		if err := p.SkipAllAnswers(); err == nil {
			if err := p.SkipAllAuthorities(); err == nil {
				for {
					r, err := p.Additional()
					if err != nil {
						break
					}
					if r.Header.Type == dnsmessage.TypeOPT {
						optRes = &r
						break
					}
				}
			}
		}
	}
	return optRes
}

const minEDNS0Size = 512  // per RFC 6891 Section 6.2.5
const maxEDNS0Size = 1232 // per DNS Flag Day 2020 recommendation

// extractEDNS0UDPSize extracts the advertised UDP buffer size from an EDNS0 OPT record
// in a DNS query packet. If no EDNS0 record is present or the packet is malformed,
// it returns 0, indicating the default 512-byte limit should be used.
func extractEDNS0UDPSize(query []byte) uint16 {
	size := uint16(0)
	optRes := extractOPTResource(query)

	if optRes != nil {
		// UDP payload size is encoded in the CLASS field of the OPT header.
		// Per RFC 6891 §6.2.5, treat any advertised UDP size smaller than 512
		// as 512. Per DNS Flag Day 2020 (https://www.dnsflagday.net/2020/),
		// the cap should be 1232 bytes, and newer versions of resolvers
		// have set 1232 as their default limit.
		size = uint16(optRes.Header.Class)
		if size < minEDNS0Size {
			size = minEDNS0Size
		}
		if size > maxEDNS0Size {
			size = maxEDNS0Size
		}
	}
	return size
}

// truncateDNSResponse performs RFC-compliant truncation of a DNS
// response message. It preserves the question section and as many
// resource records as possible in the answer, authority, and
// additional sections, setting the TC (truncated) bit if truncation
// occurs. It enforces RFC 6891 Section 7 (preserving the OPT record
// in truncated responses).
func truncateDNSResponse(resp []byte, maxSize uint16) ([]byte, error) {
	// Sanity check on maxSize. It must be at least large enough
	// to hold a minimal DNS header (12 bytes) and at least one
	// question (5 bytes).
	if maxSize < 12+5 {
		return nil, errors.New("maxSize too small to hold minimal DNS message")
	}

	var p dnsmessage.Parser

	header, err := p.Start(resp)
	if err != nil {
		return nil, err
	}

	// 1. Extract all records into slices so we can manage them.
	questions, err := p.AllQuestions()
	if err != nil {
		return nil, err
	}

	var answers, authorities, additionals []dnsmessage.Resource
	var optRes *dnsmessage.Resource

	// Helper to extract resources from a section
	extractSection := func(sectionName string) ([]dnsmessage.Resource, error) {
		var extracted []dnsmessage.Resource
		for {
			var r dnsmessage.Resource
			var err error
			switch sectionName {
			case "Ans":
				r, err = p.Answer()
			case "Auth":
				r, err = p.Authority()
			case "Add":
				r, err = p.Additional()
			}
			if err == dnsmessage.ErrSectionDone {
				return extracted, nil
			}
			if err != nil {
				return nil, err
			}

			// Identify and isolate the OPT record
			if r.Header.Type == dnsmessage.TypeOPT {
				// We found the OPT record. Save it separately.
				// (RFC 6891: Only one OPT record is allowed)
				optRes = &r
			} else {
				extracted = append(extracted, r)
			}
		}
	}

	// We must parse sections in order: Skip Questions (already got them), then Ans, Auth, Add.
	// Note: p.AllQuestions() already advanced the parser past questions.

	if answers, err = extractSection("Ans"); err != nil {
		return nil, err
	}
	if authorities, err = extractSection("Auth"); err != nil {
		return nil, err
	}
	if additionals, err = extractSection("Add"); err != nil {
		return nil, err
	}

	// 2. Try to build the FULL packet first (Happy Path).
	// If it fits, we avoid the expensive iterative logic.
	fullPacket, err := buildResponse(header, questions, answers, authorities, additionals, optRes)
	if err == nil && uint16(len(fullPacket)) <= maxSize {
		return fullPacket, nil
	}

	// 3. Truncation Path.
	// The packet is too big. We must rebuild it record-by-record until full.
	// We MUST set the TC bit.
	header.Truncated = true

	// We start with empty sections.
	var finalAns, finalAuth, finalAdd []dnsmessage.Resource

	// Define the order of candidates we want to try adding.
	// (Answers first, then Authorities, then Additionals)
	// We use a list of *slices* to iterate section by section.
	sections := []struct {
		candidates []dnsmessage.Resource
		target     *[]dnsmessage.Resource // Pointer to the slice we are building
	}{
		{answers, &finalAns},
		{authorities, &finalAuth},
		{additionals, &finalAdd},
	}

	for _, section := range sections {
		for _, candidate := range section.candidates {
			// Speculatively add this candidate to the target list
			*section.target = append(*section.target, candidate)

			// Build the packet with the current set of records + Mandatory OPT
			testPacket, err := buildResponse(header, questions, finalAns, finalAuth, finalAdd, optRes)
			if err != nil {
				return nil, err // Should not happen with valid resources
			}

			// Check size
			if uint16(len(testPacket)) > maxSize {
				// Stop! This record broke the limit.
				// Remove the last added record (backtrack).
				*section.target = (*section.target)[:len(*section.target)-1]

				// We are full. Return the last valid build.
				// Note: We need to rebuild one last time or save the previous successful 'testPacket'.
				// To be safe/clean, let's just rebuild the "safe" state.
				return buildResponse(header, questions, finalAns, finalAuth, finalAdd, optRes)
			}

			// If it fits, continue loop to add next candidate.
		}
	}

	// If we somehow finish the loop (unlikely given we failed the "Full" check), return what we have.
	return buildResponse(header, questions, finalAns, finalAuth, finalAdd, optRes)
}

// buildResponse constructs a binary DNS message from the provided slices.
// It handles the complex state machine of dnsmessage.Builder.
func buildResponse(
	h dnsmessage.Header,
	qs []dnsmessage.Question,
	ans, auths, adds []dnsmessage.Resource,
	opt *dnsmessage.Resource,
) ([]byte, error) {
	// Start with a nil buffer; Builder will allocate.
	b := dnsmessage.NewBuilder(nil, h)
	b.EnableCompression()

	// 1. Questions
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	for _, q := range qs {
		if err := b.Question(q); err != nil {
			return nil, err
		}
	}

	// 2. Answers
	if err := b.StartAnswers(); err != nil {
		return nil, err
	}
	for _, r := range ans {
		if err := addResource(&b, r); err != nil {
			return nil, err
		}
	}

	// 3. Authorities
	if err := b.StartAuthorities(); err != nil {
		return nil, err
	}
	for _, r := range auths {
		if err := addResource(&b, r); err != nil {
			return nil, err
		}
	}

	// 4. Additionals
	if err := b.StartAdditionals(); err != nil {
		return nil, err
	}
	for _, r := range adds {
		if err := addResource(&b, r); err != nil {
			return nil, err
		}
	}

	// Always append the OPT record if it exists (RFC 6891)
	if opt != nil {
		if err := addResource(&b, *opt); err != nil {
			return nil, err
		}
	}

	// Finish and return the bytes
	return b.Finish()
}

// addResource is a helper to handle the various resource types
// when adding individual resources to the Builder.
func addResource(b *dnsmessage.Builder, r dnsmessage.Resource) error {
	switch body := r.Body.(type) {
	case *dnsmessage.AResource:
		return b.AResource(r.Header, *body)
	case *dnsmessage.AAAAResource:
		return b.AAAAResource(r.Header, *body)
	case *dnsmessage.CNAMEResource:
		return b.CNAMEResource(r.Header, *body)
	case *dnsmessage.HTTPSResource:
		return b.HTTPSResource(r.Header, *body)
	case *dnsmessage.NSResource:
		return b.NSResource(r.Header, *body)
	case *dnsmessage.PTRResource:
		return b.PTRResource(r.Header, *body)
	case *dnsmessage.SOAResource:
		return b.SOAResource(r.Header, *body)
	case *dnsmessage.MXResource:
		return b.MXResource(r.Header, *body)
	case *dnsmessage.TXTResource:
		return b.TXTResource(r.Header, *body)
	case *dnsmessage.SRVResource:
		return b.SRVResource(r.Header, *body)
	case *dnsmessage.OPTResource:
		return b.OPTResource(r.Header, *body)
	case *dnsmessage.UnknownResource:
		// Handles unsupported/generic types
		return b.UnknownResource(r.Header, *body)
	default:
		return errors.New("unsupported resource body type")
	}
}
