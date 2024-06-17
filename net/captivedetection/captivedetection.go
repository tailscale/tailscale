package captivedetection

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"runtime"
	"slices"
	"strings"
	"time"

	"tailscale.com/net/dnsfallback"
	"tailscale.com/net/netmon"
)

// Endpoint represents a URL that can be used to detect a captive portal, along with the expected
// result of the HTTP request.
type Endpoint struct {
	// URL is the URL that we make an HTTP request to as part of the captive portal detection process.
	URL string
	// StatusCode is the expected HTTP status code that we expect to see in the response.
	StatusCode int
	// ExpectedContent is a string that we expect to see contained in the response body. If this is non-empty,
	// we will check that the response body contains this string. If it is empty, we will not check the response body
	// and only check the status code.
	ExpectedContent string
	// SupportsTailscaleChallenge is true if the endpoint will return the sent value of the X-Tailscale-Challenge
	// HTTP header in its HTTP response.
	SupportsTailscaleChallenge bool
}

// Timeout is the timeout for captive portal detection requests. Because the captive portal intercepting our requests
// is usually located on the LAN, this is a very short timeout.
const Timeout time.Duration = 500 * time.Millisecond

var noRedirectClient = &http.Client{
	// No redirects allowed
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},

	// Remaining fields are the same as the default client.
	Transport: http.DefaultClient.Transport,
	Jar:       http.DefaultClient.Jar,
	Timeout:   Timeout,
}

func DetectCaptivePortal(ctx context.Context, preferredDERPRegionID int, logf func(format string, a ...any)) (found bool, err error) {
	if logf == nil {
		logf = log.Printf
	}
	logf("DetectCaptivePortal started")
	stop := false
	// Here we try detecting a captive portal using *all* available interfaces on the system.
	// We consider to have found a captive portal when any interface reports one may exists.
	//
	// Why? On Darwin, until you've accepted or closed the native OS captive portal window,
	// no default route interface is available. Using a standard default http.Client will fail
	// with a `connect: network is unreachable` error unless we do this.
	interfacesErr := netmon.ForeachInterfaceAddress(func(i netmon.Interface, p netip.Prefix) {
		if stop {
			return
		}
		localAddr := p.Addr().String()
		logf("[v1] attempting to do captive portal detection on interface %s with IP %s", i.Name, localAddr)
		res, err := checkCaptivePortal(ctx, localAddr, preferredDERPRegionID, logf)
		if err != nil {
			logf("[v1] DetectCaptivePortal: %v", err)
			return
		}
		logf("[v1] DetectCaptivePortal found: %q", found)
		stop = true
		found = res
	})

	if interfacesErr != nil {
		logf("DetectCaptivePortal could not iterate on interfaces: %v", interfacesErr)
		return false, interfacesErr
	}

	logf("DetectCaptivePortal returning")
	return found, err
}

// checkCaptivePortal reports whether or not we think the system is behind a
// captive portal, detected by making a request to a URL that we know should
// return a "204 No Content" response and checking if that's what we get.
//
// The boolean return is whether we think we have a captive portal.
func checkCaptivePortal(ctx context.Context, localAddr string, preferredDERPRegionID int, logf func(format string, a ...any)) (bool, error) {

	defer noRedirectClient.CloseIdleConnections()

	endpoints := AvailableEndpoints(preferredDERPRegionID)
	if len(endpoints) == 0 {
		return false, errors.New("no endpoints available for captive portal detection")
	}

	e := endpoints[0]

	req, err := http.NewRequestWithContext(ctx, "GET", e.URL, nil)
	if err != nil {
		return false, err
	}

	if e.SupportsTailscaleChallenge {
		if u, err := url.Parse(e.URL); err == nil {
			// Note: the set of valid characters in a challenge and the total
			// length is limited; see isChallengeChar in cmd/derper for more
			// details.
			chal := "ts_" + u.Host
			req.Header.Set("X-Tailscale-Challenge", chal)
		}
	}

	// Here we specify the address of the local network interface to use, and give the
	// HTTP client a custom Dialer that uses it.
	// Why? On Darwin, until you've accepted or closed the system captive portal alert,
	// no default route interface is available, so all network requests will fail unless
	// we do this.
	addr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:0", localAddr))
	if err != nil {
		return false, err
	}
	d := &net.Dialer{LocalAddr: addr}
	dc := func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := d.Dial(network, addr)
		return conn, err
	}
	t := &http.Transport{DialContext: dc}
	noRedirectClient.Transport = t

	r, err := noRedirectClient.Do(req)
	if err != nil {
		return false, err
	}
	return e.isBehindCaptivePortal(r, logf), nil
}

// AvailableEndpoints returns a set of Endpoints which can be used for captive portal detection by performing
// one or more HTTP requests and looking at the response. The returned Endpoints are ordered by preference,
// with the most preferred Endpoint being the first in the slice.
func AvailableEndpoints(preferredDERPRegionID int) []Endpoint {
	endpoints := []Endpoint{}

	// Before anything, if we have a preferred DERP region, let's try to return that as our first result.
	preferredIPsAndHosts := []string{}
	if preferredDERPRegionID != 0 {
		hs := dnsfallback.GetDERPHostnames(preferredDERPRegionID)
		ips := dnsfallback.GetDERPIPv4s(preferredDERPRegionID)
		preferredIPsAndHosts = slices.Concat(ips, hs)
	}

	// First, try to use the DERP servers. Generate URLs for both their IPs and hostnames (IPs first).
	// These might be blocked on some networks since they are IPs and hostnames associated with Tailscale.
	derps := slices.Concat(preferredIPsAndHosts, dnsfallback.GetAllDERPIPv4s(), dnsfallback.GetAllDERPHostnames())
	for _, derp := range derps {
		url := "http://" + derp + "/generate_204"
		e := Endpoint{url, http.StatusNoContent, "", true}
		endpoints = append(endpoints, e)
	}

	// If all DERPs fail, let's try the default Tailscale coordination server. This is also blocked on some networks.
	cs := Endpoint{"http://login.tailscale.com/generate_204", http.StatusNoContent, "", true}
	endpoints = append(endpoints, cs)

	// Lastly, to be safe, let's also include some well-known captive portal detection URLs that are not under the
	// tailscale.com umbrella. These are less likely to be blocked on public networks since blocking them
	// would break captive portal detection for many devices.
	switch runtime.GOOS {
	case "windows":
		endpoints = append(endpoints, Endpoint{"http://www.msftconnecttest.com/connecttest.txt", http.StatusOK, "Microsoft Connect Test", false})
		endpoints = append(endpoints, Endpoint{"http://www.msftncsi.com/ncsi.txt", http.StatusOK, "Microsoft NCSI", false})
	case "darwin", "ios":
		endpoints = append(endpoints, Endpoint{"http://captive.apple.com/hotspot-detect.html", http.StatusOK, "Success", false})
		endpoints = append(endpoints, Endpoint{"http://www.thinkdifferent.us/", http.StatusOK, "Success", false})
		endpoints = append(endpoints, Endpoint{"http://www.airport.us/", http.StatusOK, "Success", false})
	case "android":
		endpoints = append(endpoints, Endpoint{"http://connectivitycheck.android.com/generate_204", http.StatusNoContent, "", false})
		endpoints = append(endpoints, Endpoint{"http://connectivitycheck.gstatic.com/generate_204", http.StatusNoContent, "", false})
		endpoints = append(endpoints, Endpoint{"http://play.googleapis.com/generate_204", http.StatusNoContent, "", false})
		endpoints = append(endpoints, Endpoint{"http://clients3.google.com/generate_204", http.StatusNoContent, "", false})
	default:
		endpoints = append(endpoints, Endpoint{"http://detectportal.firefox.com/success.txt", http.StatusOK, "success", false})
		endpoints = append(endpoints, Endpoint{"http://network-test.debian.org/nm", http.StatusOK, "NetworkManager is online", false})
	}

	return endpoints
}

// IsBehindCaptivePortal checks if the given HTTP response matches the expected response for the Endpoint.
// If true, it means that the device might be behind a captive portal.
// If false, it means that we are definitely not behind a captive portal.
func (e Endpoint) isBehindCaptivePortal(r *http.Response, logf func(format string, a ...any)) bool {
	defer r.Body.Close()

	logf("analyizing captive portal check response from %q", e.URL)

	if r.StatusCode == e.StatusCode {
		logf("captive portal check request returned expected status code: %d", r.StatusCode)
		if e.ExpectedContent != "" {
			b, err := io.ReadAll(io.LimitReader(r.Body, 4096))
			if err != nil {
				logf("reading captive portal check response body failed: %v", err)
				return true
			}
			hasExpectedContent := strings.Contains(string(b), e.ExpectedContent)
			if !hasExpectedContent {
				logf("captive portal check response body did not contain expected content, wanted %q, got %q", e.ExpectedContent, b)
				return true
			} else {
				logf("captive portal check response body contained expected content: %q", e.ExpectedContent)
				if e.SupportsTailscaleChallenge {
					if u, err := url.Parse(e.URL); err == nil {
						expectedResponse := "response ts_" + u.Host
						return r.Header.Get("X-Tailscale-Response") == expectedResponse
					} else {
						return false
					}
				} else {
					return false
				}
			}
		} else {
			logf("captive portal check response body was not checked since no expected content was defined for endpoint %q", e.URL)
			return false
		}
	} else {
		logf("captive portal check request returned unexpected status code: %d", r.StatusCode)
		return true
	}
}
