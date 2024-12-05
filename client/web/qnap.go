// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// qnap.go contains handlers and logic, such as authentication,
// that is specific to running the web client on QNAP.

package web

import (
	"crypto/tls"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
)

// authorizeQNAP authenticates the logged-in QNAP user and verifies that they
// are authorized to use the web client.
// If the user is not authorized to use the client, an error is returned.
func authorizeQNAP(r *http.Request) (authorized bool, err error) {
	_, resp, err := qnapAuthn(r)
	if err != nil {
		return false, err
	}
	if resp.IsAdmin == 0 {
		return false, errors.New("user is not an admin")
	}

	return true, nil
}

type qnapAuthResponse struct {
	AuthPassed int    `xml:"authPassed"`
	IsAdmin    int    `xml:"isAdmin"`
	AuthSID    string `xml:"authSid"`
	ErrorValue int    `xml:"errorValue"`
}

func qnapAuthn(r *http.Request) (string, *qnapAuthResponse, error) {
	user, err := r.Cookie("NAS_USER")
	if err != nil {
		return "", nil, err
	}
	token, err := r.Cookie("qtoken")
	if err == nil {
		return qnapAuthnQtoken(r, user.Value, token.Value)
	}
	sid, err := r.Cookie("NAS_SID")
	if err == nil {
		return qnapAuthnSid(r, user.Value, sid.Value)
	}
	return "", nil, fmt.Errorf("not authenticated by any mechanism")
}

// qnapAuthnURL returns the auth URL to use by inferring where the UI is
// running based on the request URL. This is necessary because QNAP has so
// many options, see https://github.com/tailscale/tailscale/issues/7108
// and https://github.com/tailscale/tailscale/issues/6903
func qnapAuthnURL(requestUrl string, query url.Values) string {
	in, err := url.Parse(requestUrl)
	scheme := ""
	host := ""
	if err != nil || in.Scheme == "" {
		log.Printf("Cannot parse QNAP login URL %v", err)

		// try localhost and hope for the best
		scheme = "http"
		host = "localhost"
	} else {
		scheme = in.Scheme
		host = in.Host
	}

	u := url.URL{
		Scheme:   scheme,
		Host:     host,
		Path:     "/cgi-bin/authLogin.cgi",
		RawQuery: query.Encode(),
	}

	return u.String()
}

func qnapAuthnQtoken(r *http.Request, user, token string) (string, *qnapAuthResponse, error) {
	query := url.Values{
		"qtoken": []string{token},
		"user":   []string{user},
	}
	return qnapAuthnFinish(user, qnapAuthnURL(r.URL.String(), query))
}

func qnapAuthnSid(r *http.Request, user, sid string) (string, *qnapAuthResponse, error) {
	query := url.Values{
		"sid": []string{sid},
	}
	return qnapAuthnFinish(user, qnapAuthnURL(r.URL.String(), query))
}

func qnapAuthnFinish(user, url string) (string, *qnapAuthResponse, error) {
	// QNAP Force HTTPS mode uses a self-signed certificate. Even importing
	// the QNAP root CA isn't enough, the cert doesn't have a usable CN nor
	// SAN. See https://github.com/tailscale/tailscale/issues/6903
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Get(url)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", nil, err
	}
	authResp := &qnapAuthResponse{}
	if err := xml.Unmarshal(out, authResp); err != nil {
		return "", nil, err
	}
	if authResp.AuthPassed == 0 {
		return "", nil, fmt.Errorf("not authenticated")
	}
	return user, authResp, nil
}
