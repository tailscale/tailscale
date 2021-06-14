package ssdp

import (
	"errors"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const (
	ssdpDiscover   = `"ssdp:discover"`
	ntsAlive       = `ssdp:alive`
	ntsByebye      = `ssdp:byebye`
	ntsUpdate      = `ssdp:update`
	ssdpUDP4Addr   = "239.255.255.250:1900"
	ssdpSearchPort = 1900
	methodSearch   = "M-SEARCH"
	methodNotify   = "NOTIFY"

	// SSDPAll is a value for searchTarget that searches for all devices and services.
	SSDPAll = "ssdp:all"
	// UPNPRootDevice is a value for searchTarget that searches for all root devices.
	UPNPRootDevice = "upnp:rootdevice"
)

// HTTPUClient is the interface required to perform HTTP-over-UDP requests.
type HTTPUClient interface {
	Do(
		req *http.Request,
		timeout time.Duration,
		numSends int,
	) ([]*http.Response, error)
}

// SSDPRawSearch performs a fairly raw SSDP search request, and returns the
// unique response(s) that it receives. Each response has the requested
// searchTarget, a USN, and a valid location. maxWaitSeconds states how long to
// wait for responses in seconds, and must be a minimum of 1 (the
// implementation waits an additional 100ms for responses to arrive), 2 is a
// reasonable value for this. numSends is the number of requests to send - 3 is
// a reasonable value for this.
func SSDPRawSearch(
	httpu HTTPUClient,
	searchTarget string,
	maxWaitSeconds int,
	numSends int,
) ([]*http.Response, error) {
	if maxWaitSeconds < 1 {
		return nil, errors.New("ssdp: maxWaitSeconds must be >= 1")
	}

	req := http.Request{
		Method: methodSearch,
		// TODO: Support both IPv4 and IPv6.
		Host: ssdpUDP4Addr,
		URL:  &url.URL{Opaque: "*"},
		Header: http.Header{
			// Putting headers in here avoids them being title-cased.
			// (The UPnP discovery protocol uses case-sensitive headers)
			"HOST": []string{ssdpUDP4Addr},
			"MX":   []string{strconv.FormatInt(int64(maxWaitSeconds), 10)},
			"MAN":  []string{ssdpDiscover},
			"ST":   []string{searchTarget},
		},
	}
	allResponses, err := httpu.Do(&req, time.Duration(maxWaitSeconds)*time.Second+100*time.Millisecond, numSends)
	if err != nil {
		return nil, err
	}

	isExactSearch := searchTarget != SSDPAll && searchTarget != UPNPRootDevice

	seenUSNs := make(map[string]bool)
	var responses []*http.Response
	for _, response := range allResponses {
		if response.StatusCode != 200 {
			log.Printf("ssdp: got response status code %q in search response", response.Status)
			continue
		}
		if st := response.Header.Get("ST"); isExactSearch && st != searchTarget {
			continue
		}
		usn := response.Header.Get("USN")
		if usn == "" {
			// Empty/missing USN in search response - using location instead.
			location, err := response.Location()
			if err != nil {
				// No usable location in search response - discard.
				continue
			}
			usn = location.String()
		}
		if _, alreadySeen := seenUSNs[usn]; !alreadySeen {
			seenUSNs[usn] = true
			responses = append(responses, response)
		}
	}

	return responses, nil
}
