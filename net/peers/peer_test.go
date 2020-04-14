// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package peers

import (
	"net"
	"reflect"
	"testing"
)

func TestParseCmdOutput(t *testing.T) {
	tests := []struct {
		desc   string
		input  string
		peers  []Peer
		nilErr bool
	}{
		{
			desc: "valid input",
			input: `{
  "BackendState": "",
  "Peer": {
    "peer1publickeyhere": {
      "PublicKey": "peer1publickeyhere",
      "HostName": "mgphone",
      "OS": "iOS",
      "UserID": 33022,
      "TailAddr": "100.94.00.000",
      "Addrs": [
        "derp-1",
        "192.168.68.148:57619"
      ],
      "CurAddr": "",
      "RxBytes": 0,
      "TxBytes": 0,
      "Created": "2020-03-26T22:14:53.678505853Z",
      "LastSeen": "2020-04-13T23:00:00.000000001Z",
      "LastHandshake": "0001-01-01T00:00:00Z",
      "KeepAlive": false,
      "InNetworkMap": true,
      "InMagicSock": true,
      "InEngine": true
    },
    "peer2publickeyhere": {
      "PublicKey": "peer2publickeyhere",
      "HostName": "mgmbp",
      "OS": "macOS",
      "UserID": 33022,
      "TailAddr": "100.69.00.000",
      "Addrs": [
        "derp-1",
        "192.168.68.147:53745"
      ],
      "RxBytes": 3370,
      "TxBytes": 53601,
      "Created": "2020-02-27T19:46:18.508990755Z",
      "LastSeen": "2020-04-13T23:00:00.000000001Z",
      "LastHandshake": "2020-04-13T22:54:56.258398104Z",
      "KeepAlive": true,
      "InNetworkMap": true,
      "InMagicSock": true,
      "InEngine": true
    }
  },
  "User": {
    "1234": {
      "ID": 1234,
      "LoginName": "morgan@morgangallant.com",
      "DisplayName": "Morgan Gallant",
      "ProfilePicURL": "https://lh3.googleusercontent.com/a-/AAuE7mDYhTrqpPI8wqwEBI5fJlz0dR4xdwckeugkVUcI",
      "Roles": [
        42424242
      ]
    }
  }
}`,
			peers: []Peer{
				{
					Hostname: "mgphone",
					TailAddr: net.ParseIP("100.94.00.000"),
				},
				{
					Hostname: "mgmbp",
					TailAddr: net.ParseIP("100.69.00.000"),
				},
			},
			nilErr: true,
		},
		{
			desc: "valid, but empty input",
			input: `{
  "BackendState": "",
  "Peer": {},
  "User": {
    "1234": {
      "ID": 1234,
      "LoginName": "morgan@morgangallant.com",
      "DisplayName": "Morgan Gallant",
      "ProfilePicURL": "https://lh3.googleusercontent.com/a-/AAuE7mDYhTrqpPI8wqwEBI5fJlz0dR4xdwckeugkVUcI",
      "Roles": [
        42424242
      ]
    }
  }
}`,
			peers:  []Peer{},
			nilErr: true,
		},
		{
			desc:   "error connecting to tailscaled",
			input:  "2020/04/13 23:30:04 Failed to connect to tailscaled. (safesocket.Connect: dial unix /var/run/tailscale/tailscaled.sock: connect: no such file or directory)",
			peers:  nil,
			nilErr: false,
		},
	}
	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			peers, err := parseCmdOutput([]byte(test.input))
			if test.nilErr && err != nil {
				t.Errorf("expecting nil error, got %v", err)
			} else if !test.nilErr && err == nil {
				t.Errorf("expecting non-nil error, got nil error")
			}
			if !reflect.DeepEqual(peers, test.peers) {
				t.Errorf("expecting peer list %v, got %v", test.peers, peers)
			}
		})
	}
}
