<p align="center">
  <img alt="GoReleaser Logo" src="https://avatars2.githubusercontent.com/u/24697112?v=3&s=200" height="140" />
  <h3 align="center">chglog</h3>
  <p align="center">chglog is a changelog management library and tool</p>
  <p align="center">
    <a href="https://github.com/goreleaser/chglog/releases/latest"><img alt="Release" src="https://img.shields.io/github/release/goreleaser/chglog.svg?style=for-the-badge"></a>
    <a href="/LICENSE.md"><img alt="Software License" src="https://img.shields.io/badge/license-MIT-brightgreen.svg?style=for-the-badge"></a>
    <a href="https://github.com/goreleaser/goreleaser/actions?workflow=build"><img alt="GitHub Actions" src="https://img.shields.io/github/workflow/status/goreleaser/goreleaser/build?style=for-the-badge"></a>
    <a href="https://codecov.io/gh/goreleaser/chglog"><img alt="Codecov branch" src="https://img.shields.io/codecov/c/github/goreleaser/chglog/master.svg?style=for-the-badge"></a>
    <a href="https://goreportcard.com/report/github.com/goreleaser/chglog"><img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/goreleaser/chglog?style=for-the-badge"></a>
    <a href="http://godoc.org/github.com/goreleaser/chglog"><img alt="Go Doc" src="https://img.shields.io/badge/godoc-reference-blue.svg?style=for-the-badge"></a>
    <a href="https://github.com/goreleaser"><img alt="Powered By: GoReleaser" src="https://img.shields.io/badge/powered%20by-goreleaser-green.svg?style=for-the-badge"></a>
  </p>
</p>

## Why

While there are other tool out there that will create a changelog output as part of their workflow none of the ones
I could find did so in a way that allowed formatting the output via multiple templates.

The need to multiple output formats was being driven by the desire to add changelog support to
https://github.com/goreleaser/nfpm and the deb and rpm changelog formats not being the same.

## Goals

* [x] be simple to use
* [x] provide decent default templates for deb, rpm, release, and repo style changelog formats
* [x] be distributed as a single binary
* [x] reproducible results
  * [x] depend on the fewer external things as possible
  * [x] store changelog in a transportable format (.yml)
* [x] be possible to use it as a lib in other go projects (namely [goreleaser][] itself)

## Install
`go get github.com/djgilcrease/chglog/cmd/chglog`

## Usage

The first steps are to run `chglog config` to initialize a config file (`.chglog.yml`) and edit
the generated file according to your needs:

```yaml
conventional-commits: false
deb:
  distribution: []
  urgency: ""
debug: false
owner: ""
package-name: ""

```

The next step is to run `chglog init`.
```yaml
- semver: 0.0.1
  date: 2019-10-18T16:05:33-07:00
  packager: dj gilcrease <example@example.com>
  changes:
  - commit: 2c499787328348f09ae1e8f03757c6483b9a938a
    note: |-
      oops i forgot to use Conventional Commits style message

      This should NOT break anything even if I am asking to build the changelog using Conventional Commits style message
  - commit: 3ec1e9a60d07cc060cee727c97ffc8aac5713943
    note: |-
      feat: added file two feature

      BREAKING CHANGE: this is a backwards incompatible change
  - commit: 2cc00abc77d401a541d18c26e5c7fbef1effd3ed
    note: |-
      feat: added the fileone feature

      * This is a test repo
      * so ya!
```

Then to generate a `CHANGELOG.md` file you would do `chglog format --template repo > CHANGELOG.md`

Now whenever you goto do another release you would do `chglog add --version v#.#.#` (version MUST be semver format)

And that's it!


## Usage as lib

You can look at the code of chglog itself to see how to use it as a library

## Status

* alpha

## Donate

Donations are very much appreciated! You can donate/sponsor on the main
[goreleaser opencollective](https://opencollective.com/goreleaser)! It's
easy and will surely help the developers at least buy some ☕️ or 🍺!

## Stargazers over time

[![goreleaser/chglog stargazers over time](https://starcharts.herokuapp.com/goreleaser/chglog.svg)](https://starcharts.herokuapp.com/goreleaser/chglog)

---

Would you like to fix something in the documentation? Feel free to open an [issue](https://github.com/goreleaser/chglog/issues).
