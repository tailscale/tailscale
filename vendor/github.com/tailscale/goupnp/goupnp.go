// goupnp is an implementation of a client for various UPnP services.
//
// For most uses, it is recommended to use the code-generated packages under
// github.com/tailscale/goupnp/dcps. Example use is shown at
// http://godoc.org/github.com/tailscale/goupnp/example
//
// A commonly used client is internetgateway1.WANPPPConnection1:
// http://godoc.org/github.com/tailscale/goupnp/dcps/internetgateway1#WANPPPConnection1
//
// Currently only a couple of schemas have code generated for them from the
// UPnP example XML specifications. Not all methods will work on these clients,
// because the generated stubs contain the full set of specified methods from
// the XML specifications, and the discovered services will likely support a
// subset of those methods.
package goupnp

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/tailscale/goupnp/ssdp"
)

// ContextError is an error that wraps an error with some context information.
type ContextError struct {
	Context string
	Err     error
}

func ctxError(err error, msg string) ContextError {
	return ContextError{Context: msg, Err: err}
}

func ctxErrorf(err error, msg string, args ...interface{}) ContextError {
	return ContextError{
		Context: fmt.Sprintf(msg, args...),
		Err:     err,
	}
}

func (err ContextError) Error() string {
	return fmt.Sprintf("%s: %v", err.Context, err.Err)
}

// MaybeRootDevice contains either a RootDevice or an error.
type MaybeRootDevice struct {
	// Identifier of the device.
	USN string

	// Set iff Err == nil.
	Root *RootDevice

	// The location the device was discovered at. This can be used with
	// DeviceByURL, assuming the device is still present. A location represents
	// the discovery of a device, regardless of if there was an error probing it.
	Location *url.URL

	// Any error encountered probing a discovered device.
	Err error
}

// DiscoverDevices attempts to find targets of the given type. This is
// typically the entry-point for this package. searchTarget is typically a URN
// in the form "urn:schemas-upnp-org:device:..." or
// "urn:schemas-upnp-org:service:...". A single error is returned for errors
// while attempting to send the query. An error or RootDevice is returned for
// each discovered RootDevice.
func DiscoverDevices(ctx context.Context, searchTarget string) ([]MaybeRootDevice, error) {
	hc, err := httpuClient()
	if err != nil {
		return nil, err
	}
	defer hc.Close()
	responses, err := ssdp.SSDPRawSearch(ctx, hc, string(searchTarget), 3)
	if err != nil {
		return nil, err
	}

	results := make([]MaybeRootDevice, len(responses))
	for i, response := range responses {
		maybe := &results[i]
		maybe.USN = response.Header.Get("USN")
		loc, err := response.Location()
		if err != nil {
			maybe.Err = ContextError{"unexpected bad location from search", err}
			continue
		}
		maybe.Location = loc
		if root, err := DeviceByURL(ctx, loc); err != nil {
			maybe.Err = err
		} else {
			maybe.Root = root
		}
	}

	return results, nil
}

func DeviceByURL(ctx context.Context, loc *url.URL) (*RootDevice, error) {
	locStr := loc.String()
	root := new(RootDevice)
	if err := requestXml(ctx, locStr, DeviceXMLNamespace, root); err != nil {
		return nil, ContextError{fmt.Sprintf("error requesting root device details from %q", locStr), err}
	}
	var urlBaseStr string
	if root.URLBaseStr != "" {
		urlBaseStr = root.URLBaseStr
	} else {
		urlBaseStr = locStr
	}
	urlBase, err := url.Parse(urlBaseStr)
	if err != nil {
		return nil, ContextError{fmt.Sprintf("error parsing location URL %q", locStr), err}
	}
	root.SetURLBase(urlBase)
	return root, nil
}

// CharsetReaderDefault specifies the charset reader used while decoding the output
// from a UPnP server. It can be modified in an init function to allow for non-utf8 encodings,
// but should not be changed after requesting clients.
var CharsetReaderDefault func(charset string, input io.Reader) (io.Reader, error)

// contextKey is an unexported type which prevents construction of other contextKeys.
type httpContextKey struct{}

// WithHTTPClient returns a context wrapping ctx with the HTTP client set to c.
// If c is nil, http.DefaultClient is used.
func WithHTTPClient(ctx context.Context, c *http.Client) context.Context {
	return context.WithValue(ctx, httpContextKey{}, c)
}

func httpClient(ctx context.Context) *http.Client {
	if c, _ := ctx.Value(httpContextKey{}).(*http.Client); c != nil {
		return c
	}
	return http.DefaultClient
}

func requestXml(ctx context.Context, url string, defaultSpace string, into interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := httpClient(ctx).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("goupnp: got response status %s from %q", resp.Status, url)
	}

	decoder := xml.NewDecoder(resp.Body)
	decoder.DefaultSpace = defaultSpace
	decoder.CharsetReader = CharsetReaderDefault

	return decoder.Decode(into)
}
