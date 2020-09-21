// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tshttpproxy

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/alexbrainman/sspi/negotiate"
	"golang.org/x/sys/windows"
)

var (
	winHTTP            = windows.NewLazySystemDLL("winhttp.dll")
	httpOpenProc       = winHTTP.NewProc("WinHttpOpen")
	closeHandleProc    = winHTTP.NewProc("WinHttpCloseHandle")
	getProxyForUrlProc = winHTTP.NewProc("WinHttpGetProxyForUrl")
)

func init() {
	sysProxyFromEnv = proxyFromWinHTTPOrCache
	sysAuthHeader = sysAuthHeaderWindows
}

var cachedProxy struct {
	sync.Mutex
	val *url.URL
}

func proxyFromWinHTTPOrCache(req *http.Request) (*url.URL, error) {
	if req.URL == nil {
		return nil, nil
	}
	urlStr := req.URL.String()

	ctx, cancel := context.WithTimeout(req.Context(), 5*time.Second)
	defer cancel()

	type result struct {
		proxy *url.URL
		err   error
	}
	resc := make(chan result, 1)
	go func() {
		proxy, err := proxyFromWinHTTP(ctx, urlStr)
		resc <- result{proxy, err}
	}()

	select {
	case res := <-resc:
		err := res.err
		if err == nil {
			cachedProxy.Lock()
			defer cachedProxy.Unlock()
			if was, now := fmt.Sprint(cachedProxy.val), fmt.Sprint(res.proxy); was != now {
				log.Printf("tshttpproxy: winhttp: updating cached proxy setting from %v to %v", was, now)
			}
			cachedProxy.val = res.proxy
			return res.proxy, nil
		}

		// See https://docs.microsoft.com/en-us/windows/win32/winhttp/error-messages
		const (
			ERROR_WINHTTP_AUTODETECTION_FAILED      = 12180
			ERROR_WINHTTP_UNABLE_TO_DOWNLOAD_SCRIPT = 12167
		)
		if err == syscall.Errno(ERROR_WINHTTP_AUTODETECTION_FAILED) {
			setNoProxyUntil(10 * time.Second)
			return nil, nil
		}
		log.Printf("tshttpproxy: winhttp: GetProxyForURL(%q): %v/%#v", urlStr, err, err)
		if err == syscall.Errno(ERROR_WINHTTP_UNABLE_TO_DOWNLOAD_SCRIPT) {
			setNoProxyUntil(10 * time.Second)
			return nil, nil
		}
		return nil, err
	case <-ctx.Done():
		cachedProxy.Lock()
		defer cachedProxy.Unlock()
		log.Printf("tshttpproxy: winhttp: GetProxyForURL(%q): timeout; using cached proxy %v", urlStr, cachedProxy.val)
		return cachedProxy.val, nil
	}
}

func proxyFromWinHTTP(ctx context.Context, urlStr string) (proxy *url.URL, err error) {
	whi, err := winHTTPOpen()
	if err != nil {
		log.Printf("winhttp: Open: %v", err)
		return nil, err
	}
	defer whi.Close()

	t0 := time.Now()
	v, err := whi.GetProxyForURL(urlStr)
	td := time.Since(t0).Round(time.Millisecond)
	if err := ctx.Err(); err != nil {
		log.Printf("tshttpproxy: winhttp: context canceled, ignoring GetProxyForURL(%q) after %v", urlStr, td)
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	if v == "" {
		return nil, nil
	}
	// Discard all but first proxy value for now.
	if i := strings.Index(v, ";"); i != -1 {
		v = v[:i]
	}
	if !strings.HasPrefix(v, "https://") {
		v = "http://" + v
	}
	return url.Parse(v)
}

var userAgent = windows.StringToUTF16Ptr("Tailscale")

const (
	winHTTP_ACCESS_TYPE_AUTOMATIC_PROXY = 4
	winHTTP_AUTOPROXY_ALLOW_AUTOCONFIG  = 0x00000100
	winHTTP_AUTOPROXY_AUTO_DETECT       = 1
	winHTTP_AUTO_DETECT_TYPE_DHCP       = 0x00000001
	winHTTP_AUTO_DETECT_TYPE_DNS_A      = 0x00000002
)

func winHTTPOpen() (winHTTPInternet, error) {
	if err := httpOpenProc.Find(); err != nil {
		return 0, err
	}
	r, _, err := httpOpenProc.Call(
		uintptr(unsafe.Pointer(userAgent)),
		winHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
		0, /* WINHTTP_NO_PROXY_NAME */
		0, /* WINHTTP_NO_PROXY_BYPASS */
		0)
	if r == 0 {
		return 0, err
	}
	return winHTTPInternet(r), nil
}

type winHTTPInternet windows.Handle

func (hi winHTTPInternet) Close() error {
	if err := closeHandleProc.Find(); err != nil {
		return err
	}
	r, _, err := closeHandleProc.Call(uintptr(hi))
	if r == 1 {
		return nil
	}
	return err
}

// WINHTTP_AUTOPROXY_OPTIONS
// https://docs.microsoft.com/en-us/windows/win32/api/winhttp/ns-winhttp-winhttp_autoproxy_options
type autoProxyOptions struct {
	DwFlags                uint32
	DwAutoDetectFlags      uint32
	AutoConfigUrl          *uint16
	_                      uintptr
	_                      uint32
	FAutoLogonIfChallenged bool
}

// WINHTTP_PROXY_INFO
// https://docs.microsoft.com/en-us/windows/win32/api/winhttp/ns-winhttp-winhttp_proxy_info
type winHTTPProxyInfo struct {
	AccessType  uint16
	Proxy       *uint16
	ProxyBypass *uint16
}

var proxyForURLOpts = &autoProxyOptions{
	DwFlags:           winHTTP_AUTOPROXY_ALLOW_AUTOCONFIG | winHTTP_AUTOPROXY_AUTO_DETECT,
	DwAutoDetectFlags: winHTTP_AUTO_DETECT_TYPE_DHCP, // | winHTTP_AUTO_DETECT_TYPE_DNS_A,
}

func (hi winHTTPInternet) GetProxyForURL(urlStr string) (string, error) {
	if err := getProxyForUrlProc.Find(); err != nil {
		return "", err
	}
	var out winHTTPProxyInfo
	r, _, err := getProxyForUrlProc.Call(
		uintptr(hi),
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(urlStr))),
		uintptr(unsafe.Pointer(proxyForURLOpts)),
		uintptr(unsafe.Pointer(&out)))
	if r == 1 {
		return windows.UTF16PtrToString(out.Proxy), nil
	}
	return "", err
}

func sysAuthHeaderWindows(u *url.URL) (string, error) {
	spn := "HTTP/" + u.Hostname()
	creds, err := negotiate.AcquireCurrentUserCredentials()
	if err != nil {
		return "", fmt.Errorf("negotiate.AcquireCurrentUserCredentials: %w", err)
	}
	defer creds.Release()

	secCtx, token, err := negotiate.NewClientContext(creds, spn)
	if err != nil {
		return "", fmt.Errorf("negotiate.NewClientContext: %w", err)
	}
	defer secCtx.Release()

	return "Negotiate " + base64.StdEncoding.EncodeToString(token), nil
}
