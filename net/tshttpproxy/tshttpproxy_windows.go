// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tshttpproxy

import (
	"log"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	winHTTP            = windows.NewLazySystemDLL("winhttp.dll")
	httpOpenProc       = winHTTP.NewProc("WinHttpOpen")
	closeHandleProc    = winHTTP.NewProc("WinHttpCloseHandle")
	getProxyForUrlProc = winHTTP.NewProc("WinHttpGetProxyForUrl")
)

func init() {
	sysProxyFromEnv = proxyFromWinHTTP
}

func proxyFromWinHTTP(req *http.Request) (*url.URL, error) {
	if req.URL == nil {
		return nil, nil
	}
	urlStr := req.URL.String()

	whi, err := winHTTPOpen()
	if err != nil {
		// Log but otherwise ignore the error.
		log.Printf("winhttp: Open: %v", err)
		return nil, nil
	}
	defer whi.Close()

	v, err := whi.GetProxyForURL(urlStr)
	if err != nil {
		// See https://docs.microsoft.com/en-us/windows/win32/winhttp/error-messages
		const ERROR_WINHTTP_AUTODETECTION_FAILED = 12180
		if err == syscall.Errno(ERROR_WINHTTP_AUTODETECTION_FAILED) {
			return nil, nil
		}
		log.Printf("winhttp: GetProxyForURL(%q): %v (%T, %#v)", urlStr, err, err, err)
		return nil, nil
	}
	if v != "" {
		// Discard all but first proxy value for now.
		if i := strings.Index(v, ";"); i != -1 {
			v = v[:i]
		}
		if !strings.HasPrefix(v, "https://") {
			v = "http://" + v
		}
		if u, err := url.Parse(v); err == nil {
			return u, nil
		}
	}

	return nil, nil
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
