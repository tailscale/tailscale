# Changelog

## 2.0.0-rc1 (2016-02-11)

Time flies and it has been three years since this package was first released.
There have been a couple of API changes I have wanted to do for some time but
I've tried to maintain backwards compatibility. Some inconsistencies in the
API have started to show, proper vendor support in Go out of the box and
the fact that `go vet` will give warnings -- I have decided to bump the major
version.

* Make eg. `Info` and `Infof` do different things. You want to change all calls
	to `Info` with a string format go to `Infof` etc. In many cases, `go vet` will
	guide you.
* `Id` in `Record` is now called `ID`

## 1.0.0 (2013-02-21)

Initial release
