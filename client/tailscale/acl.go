// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build go1.19

package tailscale

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
)

// ACLRow defines a rule that grants access by a set of users or groups to a set
// of servers and ports.
// Only one of Src/Dst or Users/Ports may be specified.
type ACLRow struct {
	Action string   `json:"action,omitempty"` // valid values: "accept"
	Users  []string `json:"users,omitempty"`  // old name for src
	Ports  []string `json:"ports,omitempty"`  // old name for dst
	Src    []string `json:"src,omitempty"`
	Dst    []string `json:"dst,omitempty"`
}

// ACLTest defines a test for your ACLs to prevent accidental exposure or
// revoking of access to key servers and ports. Only one of Src or User may be
// specified, and only one of Allow/Accept may be specified.
type ACLTest struct {
	Src    string   `json:"src,omitempty"`    // source
	User   string   `json:"user,omitempty"`   // old name for source
	Accept []string `json:"accept,omitempty"` // expected destination ip:port that user can access
	Deny   []string `json:"deny,omitempty"`   // expected destination ip:port that user cannot access

	Allow []string `json:"allow,omitempty"` // old name for accept
}

// ACLDetails contains all the details for an ACL.
type ACLDetails struct {
	Tests     []ACLTest           `json:"tests,omitempty"`
	ACLs      []ACLRow            `json:"acls,omitempty"`
	Groups    map[string][]string `json:"groups,omitempty"`
	TagOwners map[string][]string `json:"tagowners,omitempty"`
	Hosts     map[string]string   `json:"hosts,omitempty"`
}

// ACL contains an ACLDetails and metadata.
type ACL struct {
	ACL  ACLDetails
	ETag string // to check with version on server
}

// ACLHuJSON contains the HuJSON string of the ACL and metadata.
type ACLHuJSON struct {
	ACL      string
	Warnings []string
	ETag     string // to check with version on server
}

// ACL makes a call to the Tailscale server to get a JSON-parsed version of the ACL.
// The JSON-parsed version of the ACL contains no comments as proper JSON does not support
// comments.
func (c *Client) ACL(ctx context.Context) (acl *ACL, err error) {
	// Format return errors to be descriptive.
	defer func() {
		if err != nil {
			err = fmt.Errorf("tailscale.ACL: %w", err)
		}
	}()

	path := fmt.Sprintf("%s/api/v2/tailnet/%s/acl", c.baseURL(), c.tailnet)
	req, err := http.NewRequestWithContext(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	b, resp, err := c.sendRequest(req)
	if err != nil {
		return nil, err
	}

	// If status code was not successful, return the error.
	// TODO: Change the check for the StatusCode to include other 2XX success codes.
	if resp.StatusCode != http.StatusOK {
		return nil, handleErrorResponse(b, resp)
	}

	// Otherwise, try to decode the response.
	var aclDetails ACLDetails
	if err = json.Unmarshal(b, &aclDetails); err != nil {
		return nil, err
	}
	acl = &ACL{
		ACL:  aclDetails,
		ETag: resp.Header.Get("ETag"),
	}
	return acl, nil
}

// ACLHuJSON makes a call to the Tailscale server to get the ACL HuJSON and returns
// it as a string.
// HuJSON is JSON with a few modifications to make it more human-friendly. The primary
// changes are allowing comments and trailing comments. See the following links for more info:
// https://tailscale.com/s/acl-format
// https://github.com/tailscale/hujson
func (c *Client) ACLHuJSON(ctx context.Context) (acl *ACLHuJSON, err error) {
	// Format return errors to be descriptive.
	defer func() {
		if err != nil {
			err = fmt.Errorf("tailscale.ACLHuJSON: %w", err)
		}
	}()

	path := fmt.Sprintf("%s/api/v2/tailnet/%s/acl?details=1", c.baseURL(), c.tailnet)
	req, err := http.NewRequestWithContext(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/hujson")
	b, resp, err := c.sendRequest(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, handleErrorResponse(b, resp)
	}

	data := struct {
		ACL      []byte   `json:"acl"`
		Warnings []string `json:"warnings"`
	}{}
	if err := json.Unmarshal(b, &data); err != nil {
		return nil, err
	}

	acl = &ACLHuJSON{
		ACL:      string(data.ACL),
		Warnings: data.Warnings,
		ETag:     resp.Header.Get("ETag"),
	}
	return acl, nil
}

// ACLTestFailureSummary specifies a user for which ACL tests
// failed and the related user-friendly error messages.
//
// ACLTestFailureSummary specifies the JSON format sent to the
// JavaScript client to be rendered in the HTML.
type ACLTestFailureSummary struct {
	User     string   `json:"user,omitempty"`
	Errors   []string `json:"errors,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

// ACLTestError is ErrResponse but with an extra field to account for ACLTestFailureSummary.
type ACLTestError struct {
	ErrResponse
	Data []ACLTestFailureSummary `json:"data"`
}

func (e ACLTestError) Error() string {
	return fmt.Sprintf("%s, Data: %+v", e.ErrResponse.Error(), e.Data)
}

func (c *Client) aclPOSTRequest(ctx context.Context, body []byte, avoidCollisions bool, etag, acceptHeader string) ([]byte, string, error) {
	path := fmt.Sprintf("%s/api/v2/tailnet/%s/acl", c.baseURL(), c.tailnet)
	req, err := http.NewRequestWithContext(ctx, "POST", path, bytes.NewBuffer(body))
	if err != nil {
		return nil, "", err
	}

	if avoidCollisions {
		req.Header.Set("If-Match", etag)
	}
	req.Header.Set("Accept", acceptHeader)
	req.Header.Set("Content-Type", "application/hujson")
	b, resp, err := c.sendRequest(req)
	if err != nil {
		return nil, "", err
	}

	// If status code was not successful, return the error.
	// TODO: Change the check for the StatusCode to include other 2XX success codes.
	if resp.StatusCode != http.StatusOK {
		// check if test error
		var ate ACLTestError
		if err := json.Unmarshal(b, &ate); err != nil {
			return nil, "", err
		}
		ate.Status = resp.StatusCode
		return nil, "", ate
	}
	return b, resp.Header.Get("ETag"), nil
}

// SetACL sends a POST request to update the ACL according to the provided ACL object. If
// `avoidCollisions` is true, it will use the ETag obtained in the GET request in an If-Match
// header to check if the previously obtained ACL was the latest version and that no updates
// were missed.
//
// Returns error with status code 412 if mistmached ETag and avoidCollisions is set to true.
// Returns error if ACL has tests that fail.
// Returns error if there are other errors with the ACL.
func (c *Client) SetACL(ctx context.Context, acl ACL, avoidCollisions bool) (res *ACL, err error) {
	// Format return errors to be descriptive.
	defer func() {
		if err != nil {
			err = fmt.Errorf("tailscale.SetACL: %w", err)
		}
	}()
	postData, err := json.Marshal(acl.ACL)
	if err != nil {
		return nil, err
	}
	b, etag, err := c.aclPOSTRequest(ctx, postData, avoidCollisions, acl.ETag, "application/json")
	if err != nil {
		return nil, err
	}

	// Otherwise, try to decode the response.
	var aclDetails ACLDetails
	if err = json.Unmarshal(b, &aclDetails); err != nil {
		return nil, err
	}
	res = &ACL{
		ACL:  aclDetails,
		ETag: etag,
	}
	return res, nil
}

// SetACLHuJSON sends a POST request to update the ACL according to the provided ACL object. If
// `avoidCollisions` is true, it will use the ETag obtained in the GET request in an If-Match
// header to check if the previously obtained ACL was the latest version and that no updates
// were missed.
//
// Returns error with status code 412 if mistmached ETag and avoidCollisions is set to true.
// Returns error if the HuJSON is invalid.
// Returns error if ACL has tests that fail.
// Returns error if there are other errors with the ACL.
func (c *Client) SetACLHuJSON(ctx context.Context, acl ACLHuJSON, avoidCollisions bool) (res *ACLHuJSON, err error) {
	// Format return errors to be descriptive.
	defer func() {
		if err != nil {
			err = fmt.Errorf("tailscale.SetACLHuJSON: %w", err)
		}
	}()

	postData := []byte(acl.ACL)
	b, etag, err := c.aclPOSTRequest(ctx, postData, avoidCollisions, acl.ETag, "application/hujson")
	if err != nil {
		return nil, err
	}

	res = &ACLHuJSON{
		ACL:  string(b),
		ETag: etag,
	}
	return res, nil
}

// UserRuleMatch specifies the source users/groups/hosts that a rule targets
// and the destination ports that they can access.
// LineNumber is only useful for requests provided in HuJSON form.
// While JSON requests will have LineNumber, the value is not useful.
type UserRuleMatch struct {
	Users      []string `json:"users"`
	Ports      []string `json:"ports"`
	LineNumber int      `json:"lineNumber"`

	// Postures is a list of posture policies that are
	// associated with this match. The rules can be looked
	// up in the ACLPreviewResponse parent struct.
	// The source of the list is from srcPosture on
	// an ACL or Grant rule:
	// https://tailscale.com/kb/1288/device-posture#posture-conditions
	Postures []string `json:"postures"`
}

// ACLPreviewResponse is the response type of previewACLPostRequest
type ACLPreviewResponse struct {
	Matches    []UserRuleMatch `json:"matches"`    // ACL rules that match the specified user or ipport.
	Type       string          `json:"type"`       // The request type: currently only "user" or "ipport".
	PreviewFor string          `json:"previewFor"` // A specific user or ipport.

	// Postures is a map of postures and associated rules that apply
	// to this preview.
	// For more details about the posture mapping, see:
	// https://tailscale.com/kb/1288/device-posture#postures
	Postures map[string][]string `json:"postures,omitempty"`
}

// ACLPreview is the response type of PreviewACLForUser, PreviewACLForIPPort, PreviewACLHuJSONForUser, and PreviewACLHuJSONForIPPort
type ACLPreview struct {
	Matches []UserRuleMatch `json:"matches"`
	User    string          `json:"user,omitempty"`   // Filled if response of PreviewACLForUser or PreviewACLHuJSONForUser
	IPPort  string          `json:"ipport,omitempty"` // Filled if response of PreviewACLForIPPort or PreviewACLHuJSONForIPPort

	// Postures is a map of postures and associated rules that apply
	// to this preview.
	// For more details about the posture mapping, see:
	// https://tailscale.com/kb/1288/device-posture#postures
	Postures map[string][]string `json:"postures,omitempty"`
}

func (c *Client) previewACLPostRequest(ctx context.Context, body []byte, previewType string, previewFor string) (res *ACLPreviewResponse, err error) {
	path := fmt.Sprintf("%s/api/v2/tailnet/%s/acl/preview", c.baseURL(), c.tailnet)
	req, err := http.NewRequestWithContext(ctx, "POST", path, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	q := req.URL.Query()
	q.Add("type", previewType)
	q.Add("previewFor", previewFor)
	req.URL.RawQuery = q.Encode()

	req.Header.Set("Content-Type", "application/hujson")
	c.setAuth(req)

	b, resp, err := c.sendRequest(req)
	if err != nil {
		return nil, err
	}

	// If status code was not successful, return the error.
	// TODO: Change the check for the StatusCode to include other 2XX success codes.
	if resp.StatusCode != http.StatusOK {
		return nil, handleErrorResponse(b, resp)
	}
	if err = json.Unmarshal(b, &res); err != nil {
		return nil, err
	}

	return res, nil
}

// PreviewACLForUser determines what rules match a given ACL for a user.
// The ACL can be a locally modified or clean ACL obtained from server.
//
// Returns ACLPreview on success with matches in a slice. If there are no matches,
// the call is still successful but Matches will be an empty slice.
// Returns error if the provided ACL is invalid.
func (c *Client) PreviewACLForUser(ctx context.Context, acl ACL, user string) (res *ACLPreview, err error) {
	// Format return errors to be descriptive.
	defer func() {
		if err != nil {
			err = fmt.Errorf("tailscale.PreviewACLForUser: %w", err)
		}
	}()
	postData, err := json.Marshal(acl.ACL)
	if err != nil {
		return nil, err
	}
	b, err := c.previewACLPostRequest(ctx, postData, "user", user)
	if err != nil {
		return nil, err
	}

	return &ACLPreview{
		Matches:  b.Matches,
		User:     b.PreviewFor,
		Postures: b.Postures,
	}, nil
}

// PreviewACLForIPPort determines what rules match a given ACL for a ipport.
// The ACL can be a locally modified or clean ACL obtained from server.
//
// Returns ACLPreview on success with matches in a slice. If there are no matches,
// the call is still successful but Matches will be an empty slice.
// Returns error if the provided ACL is invalid.
func (c *Client) PreviewACLForIPPort(ctx context.Context, acl ACL, ipport netip.AddrPort) (res *ACLPreview, err error) {
	// Format return errors to be descriptive.
	defer func() {
		if err != nil {
			err = fmt.Errorf("tailscale.PreviewACLForIPPort: %w", err)
		}
	}()
	postData, err := json.Marshal(acl.ACL)
	if err != nil {
		return nil, err
	}
	b, err := c.previewACLPostRequest(ctx, postData, "ipport", ipport.String())
	if err != nil {
		return nil, err
	}

	return &ACLPreview{
		Matches:  b.Matches,
		IPPort:   b.PreviewFor,
		Postures: b.Postures,
	}, nil
}

// PreviewACLHuJSONForUser determines what rules match a given ACL for a user.
// The ACL can be a locally modified or clean ACL obtained from server.
//
// Returns ACLPreview on success with matches in a slice. If there are no matches,
// the call is still successful but Matches will be an empty slice.
// Returns error if the provided ACL is invalid.
func (c *Client) PreviewACLHuJSONForUser(ctx context.Context, acl ACLHuJSON, user string) (res *ACLPreview, err error) {
	// Format return errors to be descriptive.
	defer func() {
		if err != nil {
			err = fmt.Errorf("tailscale.PreviewACLHuJSONForUser: %w", err)
		}
	}()
	postData := []byte(acl.ACL)
	b, err := c.previewACLPostRequest(ctx, postData, "user", user)
	if err != nil {
		return nil, err
	}

	return &ACLPreview{
		Matches:  b.Matches,
		User:     b.PreviewFor,
		Postures: b.Postures,
	}, nil
}

// PreviewACLHuJSONForIPPort determines what rules match a given ACL for a ipport.
// The ACL can be a locally modified or clean ACL obtained from server.
//
// Returns ACLPreview on success with matches in a slice. If there are no matches,
// the call is still successful but Matches will be an empty slice.
// Returns error if the provided ACL is invalid.
func (c *Client) PreviewACLHuJSONForIPPort(ctx context.Context, acl ACLHuJSON, ipport string) (res *ACLPreview, err error) {
	// Format return errors to be descriptive.
	defer func() {
		if err != nil {
			err = fmt.Errorf("tailscale.PreviewACLHuJSONForIPPort: %w", err)
		}
	}()
	postData := []byte(acl.ACL)
	b, err := c.previewACLPostRequest(ctx, postData, "ipport", ipport)
	if err != nil {
		return nil, err
	}

	return &ACLPreview{
		Matches:  b.Matches,
		IPPort:   b.PreviewFor,
		Postures: b.Postures,
	}, nil
}

// ValidateACLJSON takes in the given source and destination (in this situation,
// it is assumed that you are checking whether the source can connect to destination)
// and creates an ACLTest from that. It then sends the ACLTest to the control api acl
// validate endpoint, where the test is run. It returns a nil ACLTestError pointer if
// no test errors occur.
func (c *Client) ValidateACLJSON(ctx context.Context, source, dest string) (testErr *ACLTestError, err error) {
	// Format return errors to be descriptive.
	defer func() {
		if err != nil {
			err = fmt.Errorf("tailscale.ValidateACLJSON: %w", err)
		}
	}()

	tests := []ACLTest{{User: source, Allow: []string{dest}}}
	postData, err := json.Marshal(tests)
	if err != nil {
		return nil, err
	}

	path := fmt.Sprintf("%s/api/v2/tailnet/%s/acl/validate", c.baseURL(), c.tailnet)
	req, err := http.NewRequestWithContext(ctx, "POST", path, bytes.NewBuffer(postData))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	c.setAuth(req)

	b, resp, err := c.sendRequest(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("control api responded with %d status code", resp.StatusCode)
	}

	// The test ran without fail
	if len(b) == 0 {
		return nil, nil
	}

	var res ACLTestError
	// The test returned errors.
	if err = json.Unmarshal(b, &res); err != nil {
		// failed to unmarshal
		return nil, err
	}
	return &res, nil
}
