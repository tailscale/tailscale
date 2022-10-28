// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// netlogfmt parses a stream of JSON log messages from stdin and
// formats the network traffic logs produced by "tailscale.com/wgengine/netlog"
// according to the schema in "tailscale.com/types/netlogtype.Message"
// in a more humanly readable format.
//
// Example usage:
//
//	$ cat netlog.json | go run tailscale.com/cmd/netlogfmt
//	=========================================================================================
//	NodeID: n123456CNTRL
//	Logged: 2022-10-13T20:23:10.165Z
//	Window: 2022-10-13T20:23:09.644Z (5s)
//	---------------------------------------------------  Tx[P/s]  Tx[B/s]  Rx[P/s]    Rx[B/s]
//	VirtualTraffic:                                       16.80    1.64Ki   11.20      1.03Ki
//	    TCP:    100.109.51.95:22 -> 100.85.80.41:42912    16.00    1.59Ki   10.40   1008.84
//	    TCP: 100.109.51.95:21291 -> 100.107.177.2:53133    0.40   27.60      0.40     24.20
//	    TCP: 100.109.51.95:21291 -> 100.107.177.2:53134    0.40   23.40      0.40     24.20
//	PhysicalTraffic:                                      16.80    2.32Ki   11.20      1.48Ki
//	                100.85.80.41 -> 192.168.0.101:41641   16.00    2.23Ki   10.40      1.40Ki
//	               100.107.177.2 -> 192.168.0.100:41641    0.80   83.20      0.80     83.20
//	=========================================================================================
package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dsnet/try"
	jsonv2 "github.com/go-json-experiment/json"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	"tailscale.com/logtail"
	"tailscale.com/types/netlogtype"
	"tailscale.com/util/must"
)

var (
	resolveNames = flag.Bool("resolve-names", false, "convert tailscale IP addresses to hostnames; must also specify --api-key and --tailnet-id")
	apiKey       = flag.String("api-key", "", "API key to query the Tailscale API with; see https://login.tailscale.com/admin/settings/keys")
	tailnetName  = flag.String("tailnet-name", "", "tailnet domain name to lookup devices in; see https://login.tailscale.com/admin/settings/general")
)

var namesByAddr map[netip.Addr]string

func main() {
	flag.Parse()
	if *resolveNames {
		namesByAddr = mustMakeNamesByAddr()
	}

	// The logic handles a stream of arbitrary JSON.
	// So long as a JSON object seems like a network log message,
	// then this will unmarshal and print it.
	if err := processStream(os.Stdin); err != nil {
		if err == io.EOF {
			return
		}
		log.Fatalf("processStream: %v", err)
	}
}

func processStream(r io.Reader) (err error) {
	defer try.Handle(&err)
	dec := jsonv2.NewDecoder(os.Stdin)
	for {
		processValue(dec)
	}
}

func processValue(dec *jsonv2.Decoder) {
	switch dec.PeekKind() {
	case '[':
		processArray(dec)
	case '{':
		processObject(dec)
	default:
		try.E(dec.SkipValue())
	}
}

func processArray(dec *jsonv2.Decoder) {
	try.E1(dec.ReadToken()) // parse '['
	for dec.PeekKind() != ']' {
		processValue(dec)
	}
	try.E1(dec.ReadToken()) // parse ']'
}

func processObject(dec *jsonv2.Decoder) {
	var hasTraffic bool
	var rawMsg []byte
	try.E1(dec.ReadToken()) // parse '{'
	for dec.PeekKind() != '}' {
		// Capture any members that could belong to a network log message.
		switch name := try.E1(dec.ReadToken()); name.String() {
		case "virtualTraffic", "subnetTraffic", "exitTraffic", "physicalTraffic":
			hasTraffic = true
			fallthrough
		case "logtail", "nodeId", "logged", "start", "end":
			if len(rawMsg) == 0 {
				rawMsg = append(rawMsg, '{')
			} else {
				rawMsg = append(rawMsg[:len(rawMsg)-1], ',')
			}
			rawMsg = append(append(append(rawMsg, '"'), name.String()...), '"')
			rawMsg = append(rawMsg, ':')
			rawMsg = append(rawMsg, try.E1(dec.ReadValue())...)
			rawMsg = append(rawMsg, '}')
		default:
			processValue(dec)
		}
	}
	try.E1(dec.ReadToken()) // parse '}'

	// If this appears to be a network log message, then unmarshal and print it.
	if hasTraffic {
		var msg message
		try.E(jsonv2.Unmarshal(rawMsg, &msg))
		printMessage(msg)
	}
}

type message struct {
	Logtail struct {
		ID     logtail.PublicID `json:"id"`
		Logged time.Time        `json:"server_time"`
	} `json:"logtail"`
	Logged time.Time `json:"logged"`
	netlogtype.Message
}

func printMessage(msg message) {
	// Construct a table of network traffic per connection.
	rows := [][7]string{{3: "Tx[P/s]", 4: "Tx[B/s]", 5: "Rx[P/s]", 6: "Rx[B/s]"}}
	duration := msg.End.Sub(msg.Start)
	addRows := func(heading string, traffic []netlogtype.ConnectionCounts) {
		if len(traffic) == 0 {
			return
		}
		slices.SortFunc(traffic, func(x, y netlogtype.ConnectionCounts) bool {
			nx := x.TxPackets + x.TxBytes + x.RxPackets + x.RxBytes
			ny := y.TxPackets + y.TxBytes + y.RxPackets + y.RxBytes
			return nx > ny
		})
		var sum netlogtype.Counts
		for _, cc := range traffic {
			sum = sum.Add(cc.Counts)
		}
		rows = append(rows, [7]string{
			0: heading + ":",
			3: formatSI(float64(sum.TxPackets) / duration.Seconds()),
			4: formatIEC(float64(sum.TxBytes) / duration.Seconds()),
			5: formatSI(float64(sum.RxPackets) / duration.Seconds()),
			6: formatIEC(float64(sum.RxBytes) / duration.Seconds()),
		})
		if len(traffic) == 1 && traffic[0].Connection.IsZero() {
			return // this is already a summary counts
		}
		formatAddrPort := func(a netip.AddrPort) string {
			if !a.IsValid() {
				return ""
			}
			if name, ok := namesByAddr[a.Addr()]; ok {
				if a.Port() == 0 {
					return name
				}
				return name + ":" + strconv.Itoa(int(a.Port()))
			}
			if a.Port() == 0 {
				return a.Addr().String()
			}
			return a.String()
		}
		for _, cc := range traffic {
			row := [7]string{
				0: "    ",
				1: formatAddrPort(cc.Src),
				2: formatAddrPort(cc.Dst),
				3: formatSI(float64(cc.TxPackets) / duration.Seconds()),
				4: formatIEC(float64(cc.TxBytes) / duration.Seconds()),
				5: formatSI(float64(cc.RxPackets) / duration.Seconds()),
				6: formatIEC(float64(cc.RxBytes) / duration.Seconds()),
			}
			if cc.Proto > 0 {
				row[0] += cc.Proto.String() + ":"
			}
			rows = append(rows, row)
		}
	}
	addRows("VirtualTraffic", msg.VirtualTraffic)
	addRows("SubnetTraffic", msg.SubnetTraffic)
	addRows("ExitTraffic", msg.ExitTraffic)
	addRows("PhysicalTraffic", msg.PhysicalTraffic)

	// Compute the maximum width of each field.
	var maxWidths [7]int
	for _, row := range rows {
		for i, col := range row {
			if maxWidths[i] < len(col) && !(i == 0 && !strings.HasPrefix(col, " ")) {
				maxWidths[i] = len(col)
			}
		}
	}
	var maxSum int
	for _, n := range maxWidths {
		maxSum += n
	}

	// Output a table of network traffic per connection.
	line := make([]byte, 0, maxSum+len(" ")+len(" -> ")+4*len("  "))
	line = appendRepeatByte(line, '=', cap(line))
	fmt.Println(string(line))
	if !msg.Logtail.ID.IsZero() {
		fmt.Printf("LogID:  %s\n", msg.Logtail.ID)
	}
	if msg.NodeID != "" {
		fmt.Printf("NodeID: %s\n", msg.NodeID)
	}
	formatTime := func(t time.Time) string {
		return t.In(time.Local).Format("2006-01-02 15:04:05.000")
	}
	switch {
	case !msg.Logged.IsZero():
		fmt.Printf("Logged: %s\n", formatTime(msg.Logged))
	case !msg.Logtail.Logged.IsZero():
		fmt.Printf("Logged: %s\n", formatTime(msg.Logtail.Logged))
	}
	fmt.Printf("Window: %s (%0.3fs)\n", formatTime(msg.Start), duration.Seconds())
	for i, row := range rows {
		line = line[:0]
		isHeading := !strings.HasPrefix(row[0], " ")
		for j, col := range row {
			if isHeading && j == 0 {
				col = "" // headings will be printed later
			}
			switch j {
			case 0, 2: // left justified
				line = append(line, col...)
				line = appendRepeatByte(line, ' ', maxWidths[j]-len(col))
			case 1, 3, 4, 5, 6: // right justified
				line = appendRepeatByte(line, ' ', maxWidths[j]-len(col))
				line = append(line, col...)
			}
			switch j {
			case 0:
				line = append(line, " "...)
			case 1:
				if row[1] == "" && row[2] == "" {
					line = append(line, "    "...)
				} else {
					line = append(line, " -> "...)
				}
			case 2, 3, 4, 5:
				line = append(line, "  "...)
			}
		}
		switch {
		case i == 0: // print dashed-line table heading
			line = appendRepeatByte(line[:0], '-', maxWidths[0]+len(" ")+maxWidths[1]+len(" -> ")+maxWidths[2])[:cap(line)]
		case isHeading:
			copy(line[:], row[0])
		}
		fmt.Println(string(line))
	}
}

func mustMakeNamesByAddr() map[netip.Addr]string {
	switch {
	case *apiKey == "":
		log.Fatalf("--api-key must be specified with --resolve-names")
	case *tailnetName == "":
		log.Fatalf("--tailnet must be specified with --resolve-names")
	}

	// Query the Tailscale API for a list of devices in the tailnet.
	const apiURL = "https://api.tailscale.com/api/v2"
	req := must.Get(http.NewRequest("GET", apiURL+"/tailnet/"+*tailnetName+"/devices", nil))
	req.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(*apiKey+":")))
	resp := must.Get(http.DefaultClient.Do(req))
	defer resp.Body.Close()
	b := must.Get(io.ReadAll(resp.Body))
	if resp.StatusCode != 200 {
		log.Fatalf("http: %v: %s", http.StatusText(resp.StatusCode), b)
	}

	// Unmarshal the API response.
	var m struct {
		Devices []struct {
			Name  string       `json:"name"`
			Addrs []netip.Addr `json:"addresses"`
		} `json:"devices"`
	}
	must.Do(json.Unmarshal(b, &m))

	// Construct a unique mapping of Tailscale IP addresses to hostnames.
	// For brevity, we start with the first segment of the name and
	// use more segments until we find the shortest prefix that is unique
	// for all names in the tailnet.
	seen := make(map[string]bool)
	namesByAddr := make(map[netip.Addr]string)
retry:
	for i := 0; i < 10; i++ {
		maps.Clear(seen)
		maps.Clear(namesByAddr)
		for _, d := range m.Devices {
			name := fieldPrefix(d.Name, i)
			if seen[name] {
				continue retry
			}
			seen[name] = true
			for _, a := range d.Addrs {
				namesByAddr[a] = name
			}
		}
		return namesByAddr
	}
	panic("unable to produce unique mapping of address to names")
}

// fieldPrefix returns the first n number of dot-separated segments.
//
// Example:
//
//	fieldPrefix("foo.bar.baz", 0) returns ""
//	fieldPrefix("foo.bar.baz", 1) returns "foo"
//	fieldPrefix("foo.bar.baz", 2) returns "foo.bar"
//	fieldPrefix("foo.bar.baz", 3) returns "foo.bar.baz"
//	fieldPrefix("foo.bar.baz", 4) returns "foo.bar.baz"
func fieldPrefix(s string, n int) string {
	s0 := s
	for i := 0; i < n && len(s) > 0; i++ {
		if j := strings.IndexByte(s, '.'); j >= 0 {
			s = s[j+1:]
		} else {
			s = ""
		}
	}
	return strings.TrimSuffix(s0[:len(s0)-len(s)], ".")
}

func appendRepeatByte(b []byte, c byte, n int) []byte {
	for i := 0; i < n; i++ {
		b = append(b, c)
	}
	return b
}

func formatSI(n float64) string {
	switch n := math.Abs(n); {
	case n < 1e3:
		return fmt.Sprintf("%0.2f ", n/(1e0))
	case n < 1e6:
		return fmt.Sprintf("%0.2fk", n/(1e3))
	case n < 1e9:
		return fmt.Sprintf("%0.2fM", n/(1e6))
	default:
		return fmt.Sprintf("%0.2fG", n/(1e9))
	}
}

func formatIEC(n float64) string {
	switch n := math.Abs(n); {
	case n < 1<<10:
		return fmt.Sprintf("%0.2f  ", n/(1<<0))
	case n < 1<<20:
		return fmt.Sprintf("%0.2fKi", n/(1<<10))
	case n < 1<<30:
		return fmt.Sprintf("%0.2fMi", n/(1<<20))
	default:
		return fmt.Sprintf("%0.2fGi", n/(1<<30))
	}
}
