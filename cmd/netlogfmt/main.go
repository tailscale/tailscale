// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

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
	"cmp"
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
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/dsnet/try"
	jsonv2 "github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
	"tailscale.com/tailcfg"
	"tailscale.com/types/bools"
	"tailscale.com/types/logid"
	"tailscale.com/types/netlogtype"
	"tailscale.com/util/must"
)

var (
	resolveNames = flag.Bool("resolve-names", false, "This is equivalent to specifying \"--resolve-addrs=name\".")
	resolveAddrs = flag.String("resolve-addrs", "", "Resolve each tailscale IP address as a node ID, name, or user.\n"+
		"If network flow logs do not support embedded node information,\n"+
		"then --api-key and --tailnet-name must also be provided.\n"+
		"Valid values include \"nodeId\", \"name\", or \"user\".")
	apiKey      = flag.String("api-key", "", "The API key to query the Tailscale API with.\nSee https://login.tailscale.com/admin/settings/keys")
	tailnetName = flag.String("tailnet-name", "", "The Tailnet name to lookup nodes within.\nSee https://login.tailscale.com/admin/settings/general")
)

var (
	tailnetNodesByAddr map[netip.Addr]netlogtype.Node
	tailnetNodesByID   map[tailcfg.StableNodeID]netlogtype.Node
)

func main() {
	flag.Parse()
	if *resolveNames {
		*resolveAddrs = "name"
	}
	*resolveAddrs = strings.ToLower(*resolveAddrs)             // make case-insensitive
	*resolveAddrs = strings.TrimSuffix(*resolveAddrs, "s")     // allow plural form
	*resolveAddrs = strings.ReplaceAll(*resolveAddrs, " ", "") // ignore spaces
	*resolveAddrs = strings.ReplaceAll(*resolveAddrs, "-", "") // ignore dashes
	*resolveAddrs = strings.ReplaceAll(*resolveAddrs, "_", "") // ignore underscores
	switch *resolveAddrs {
	case "id", "nodeid":
		*resolveAddrs = "nodeid"
	case "name", "hostname":
		*resolveAddrs = "name"
	case "user", "tag", "usertag", "taguser":
		*resolveAddrs = "user" // tag resolution is implied
	default:
		log.Fatalf("--resolve-addrs must be \"nodeId\", \"name\", or \"user\"")
	}

	mustLoadTailnetNodes()

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
	dec := jsontext.NewDecoder(os.Stdin)
	for {
		processValue(dec)
	}
}

func processValue(dec *jsontext.Decoder) {
	switch dec.PeekKind() {
	case '[':
		processArray(dec)
	case '{':
		processObject(dec)
	default:
		try.E(dec.SkipValue())
	}
}

func processArray(dec *jsontext.Decoder) {
	try.E1(dec.ReadToken()) // parse '['
	for dec.PeekKind() != ']' {
		processValue(dec)
	}
	try.E1(dec.ReadToken()) // parse ']'
}

func processObject(dec *jsontext.Decoder) {
	var hasTraffic bool
	var rawMsg jsontext.Value
	try.E1(dec.ReadToken()) // parse '{'
	for dec.PeekKind() != '}' {
		// Capture any members that could belong to a network log message.
		switch name := try.E1(dec.ReadToken()); name.String() {
		case "virtualTraffic", "subnetTraffic", "exitTraffic", "physicalTraffic":
			hasTraffic = true
			fallthrough
		case "logtail", "nodeId", "logged", "srcNode", "dstNodes", "start", "end":
			if len(rawMsg) == 0 {
				rawMsg = append(rawMsg, '{')
			} else {
				rawMsg = append(rawMsg[:len(rawMsg)-1], ',')
			}
			rawMsg, _ = jsontext.AppendQuote(rawMsg, name.String())
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
		ID     logid.PublicID `json:"id"`
		Logged time.Time      `json:"server_time"`
	} `json:"logtail"`
	Logged time.Time `json:"logged"`
	netlogtype.Message
}

func printMessage(msg message) {
	var nodesByAddr map[netip.Addr]netlogtype.Node
	var tailnetDNS string // e.g., ".acme-corp.ts.net"
	if *resolveAddrs != "" {
		nodesByAddr = make(map[netip.Addr]netlogtype.Node)
		insertNode := func(node netlogtype.Node) {
			for _, addr := range node.Addresses {
				nodesByAddr[addr] = node
			}
		}
		for _, node := range msg.DstNodes {
			insertNode(node)
		}
		insertNode(msg.SrcNode)

		// Derive the Tailnet DNS of the self node.
		detectTailnetDNS := func(nodeName string) {
			if prefix, ok := strings.CutSuffix(nodeName, ".ts.net"); ok {
				if i := strings.LastIndexByte(prefix, '.'); i > 0 {
					tailnetDNS = nodeName[i:]
				}
			}
		}
		detectTailnetDNS(msg.SrcNode.Name)
		detectTailnetDNS(tailnetNodesByID[msg.NodeID].Name)
	}

	// Construct a table of network traffic per connection.
	rows := [][7]string{{3: "Tx[P/s]", 4: "Tx[B/s]", 5: "Rx[P/s]", 6: "Rx[B/s]"}}
	duration := msg.End.Sub(msg.Start)
	addRows := func(heading string, traffic []netlogtype.ConnectionCounts) {
		if len(traffic) == 0 {
			return
		}
		slices.SortFunc(traffic, func(x, y netlogtype.ConnectionCounts) int {
			nx := x.TxPackets + x.TxBytes + x.RxPackets + x.RxBytes
			ny := y.TxPackets + y.TxBytes + y.RxPackets + y.RxBytes
			return cmp.Compare(ny, nx)
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
			name := a.Addr().String()
			node, ok := tailnetNodesByAddr[a.Addr()]
			if !ok {
				node, ok = nodesByAddr[a.Addr()]
			}
			if ok {
				switch *resolveAddrs {
				case "nodeid":
					name = cmp.Or(string(node.NodeID), name)
				case "name":
					name = cmp.Or(strings.TrimSuffix(string(node.Name), tailnetDNS), name)
				case "user":
					name = cmp.Or(bools.IfElse(len(node.Tags) > 0, fmt.Sprint(node.Tags), node.User), name)
				}
			}
			if a.Port() != 0 {
				return name + ":" + strconv.Itoa(int(a.Port()))
			}
			return name
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

func mustLoadTailnetNodes() {
	switch {
	case *apiKey == "" && *tailnetName == "":
		return // rely on embedded node information in the logs themselves
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
		Devices []netlogtype.Node `json:"devices"`
	}
	must.Do(json.Unmarshal(b, &m))

	// Construct a mapping of Tailscale IP addresses to node information.
	tailnetNodesByAddr = make(map[netip.Addr]netlogtype.Node)
	tailnetNodesByID = make(map[tailcfg.StableNodeID]netlogtype.Node)
	for _, node := range m.Devices {
		for _, addr := range node.Addresses {
			tailnetNodesByAddr[addr] = node
		}
		tailnetNodesByID[node.NodeID] = node
	}
}

func appendRepeatByte(b []byte, c byte, n int) []byte {
	for range n {
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
