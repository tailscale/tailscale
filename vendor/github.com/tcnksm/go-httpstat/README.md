# go-httpstat [![Go Documentation](http://img.shields.io/badge/go-documentation-blue.svg?style=flat-square)][godocs] [![Build Status](http://img.shields.io/travis/tcnksm/go-httpstat.svg?style=flat-square)][travis] [![MIT License](http://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)][license] 

[godocs]: http://godoc.org/github.com/tcnksm/go-httpstat
[travis]: https://travis-ci.org/tcnksm/go-httpstat
[license]: /LICENSE

`go-httpstat` is a golang package to trace golang HTTP request latency (DNSLookup, TCP Connection and so on). Because it uses [`httptrace`](https://golang.org/pkg/net/http/httptrace/) internally, just creating `go-httpstat` powered `context` and giving it your `http.Request` kicks tracing (no big code modification is required). The original idea came from [`httpstat`](https://github.com/reorx/httpstat) command ( and Dave Cheney's [golang implementation](https://github.com/davecheney/httpstat)) 👏. This package now traces same latency infomation as them.

See usage and example on [GoDoc][godocs]. 

*NOTE*: Since [`httptrace`](https://golang.org/pkg/net/http/httptrace/) was introduced after go1.7, this package may not work with old HTTP client. Especially, if you don't use `net.DialContext` it can not trace DNS and connection. 

## Install 

Use `go get`,

```bash
$ go get github.com/tcnksm/go-httpstat
```

## Author

[Taichi Nakashima](https://github.com/tcnksm)
