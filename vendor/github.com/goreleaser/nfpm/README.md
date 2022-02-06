<p align="center">
  <img alt="GoReleaser Logo" src="https://avatars2.githubusercontent.com/u/24697112?v=3&s=200" height="140" />
  <h3 align="center">NFPM</h3>
  <p align="center">NFPM is Not FPM - a simple deb, rpm and apk packager written in Go.</p>
  <p align="center">
    <a href="https://github.com/goreleaser/nfpm/releases/latest"><img alt="Release" src="https://img.shields.io/github/release/goreleaser/nfpm.svg?style=for-the-badge"></a>
    <a href="/LICENSE.md"><img alt="Software License" src="https://img.shields.io/badge/license-MIT-brightgreen.svg?style=for-the-badge"></a>
    <a href="https://github.com/goreleaser/nfpm/actions?workflow=build"><img alt="GitHub Actions" src="https://img.shields.io/github/workflow/status/goreleaser/nfpm/build?style=for-the-badge"></a>
    <a href="https://codecov.io/gh/goreleaser/nfpm"><img alt="Codecov branch" src="https://img.shields.io/codecov/c/github/goreleaser/nfpm/master.svg?style=for-the-badge"></a>
    <a href="https://goreportcard.com/report/github.com/goreleaser/nfpm"><img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/goreleaser/nfpm?style=for-the-badge"></a>
    <a href="http://godoc.org/github.com/goreleaser/nfpm"><img alt="Go Doc" src="https://img.shields.io/badge/godoc-reference-blue.svg?style=for-the-badge"></a>
    <a href="https://github.com/goreleaser"><img alt="Powered By: GoReleaser" src="https://img.shields.io/badge/powered%20by-goreleaser-green.svg?style=for-the-badge"></a>
  </p>
</p>

## Why

While [fpm][] is great, for me, it is a bummer that it depends on `ruby`, `tar`
and other softwares.

I wanted something that could be used as a binary and/or as a library and that
was really simple.

So I created NFPM: a simpler, 0-dependency, as-little-assumptions-as-possible alternative to fpm.

## Usage

Check the documentation at https://nfpm.goreleaser.com

## Special thanks 🙏

Thanks to the [fpm][] authors for fpm, which inspires nfpm a lot.

## Donate

Donations are very much appreciated! You can donate/sponsor on the main
[goreleaser opencollective](https://opencollective.com/goreleaser)! It's
easy and will surely help the developers at least buy some ☕️ or 🍺!

## Stargazers over time

[![goreleaser/nfpm stargazers over time](https://starcharts.herokuapp.com/goreleaser/nfpm.svg)](https://starcharts.herokuapp.com/goreleaser/nfpm)

---

Would you like to fix something in the documentation? Feel free to open an [issue](https://github.com/goreleaser/nfpm/issues).

[goreleaser]: https://goreleaser.com/#linux_packages.nfpm
[fpm]: https://github.com/jordansissel/fpm
