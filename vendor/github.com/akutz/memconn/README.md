# MemConn [![GoDoc](https://godoc.org/github.com/akutz/memconn?status.svg)](http://godoc.org/github.com/akutz/memconn) [![Build Status](http://travis-ci.org/akutz/memconn.svg?branch=master)](https://travis-ci.org/akutz/memconn) [![Go Report Card](http://goreportcard.com/badge/akutz/memconn)](http://goreportcard.com/report/akutz/memconn)
MemConn provides named, in-memory network connections for Go.

## Create a Server
A new `net.Listener` used to serve HTTP, gRPC, etc. is created with
`memconn.Listen`:

```go
lis, err := memconn.Listen("memu", "UniqueName")
```

## Creating a Client (Dial)
Clients can dial any named connection:

```go
client, err := memconn.Dial("memu", "UniqueName")
```

## Network Types
MemCon supports the following network types:

| Network | Description |
|---------|-------------|
| `memb`  | A buffered, in-memory implementation of `net.Conn` |
| `memu`  | An unbuffered, in-memory implementation of `net.Conn` |

## Performance
The benchmark results illustrate MemConn's performance versus TCP
and UNIX domain sockets:

![ops](https://imgur.com/o8mXla6.png "Ops (Larger is Better)")
![ns/op](https://imgur.com/8YvPmMU.png "Nanoseconds/Op (Smaller is Better)")
![B/op](https://imgur.com/vQSfIR2.png "Bytes/Op (Smaller is Better)")
![allocs/op](https://imgur.com/k263257.png "Allocs/Op (Smaller is Better)")

MemConn is more performant than TCP and UNIX domain sockets with respect
to the CPU. While MemConn does allocate more memory, this is to be expected
since MemConn is an in-memory implementation of the `net.Conn` interface.
