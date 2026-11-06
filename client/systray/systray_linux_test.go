// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package systray

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	dbus "github.com/godbus/dbus/v5"
	"tailscale.com/client/local"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/util/cibuild"
)

// startSessionBus starts a private dbus session bus for the test and
// returns its address. The bus is terminated when the test ends.
func startSessionBus(t *testing.T) string {
	t.Helper()
	cmd := exec.Command("dbus-daemon", "--session", "--nofork", "--print-address=1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting dbus-daemon: %v", err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		t.Fatalf("reading dbus-daemon address: %v", err)
	}
	return strings.TrimSpace(line)
}

// fakeNotifierWatcher implements just enough of org.kde.StatusNotifierWatcher
// to receive item registrations from the systray app.
type fakeNotifierWatcher struct {
	registered chan string
}

// RegisterStatusNotifierItem is called over dbus by the systray app to
// announce its tray icon. It records the registration and reports success.
func (w *fakeNotifierWatcher) RegisterStatusNotifierItem(service string) *dbus.Error {
	select {
	case w.registered <- service:
	default:
	}
	return nil
}

// startFakeWatcher stands in for the desktop environment's system tray host
// on the session bus at addr.
//
// On a real desktop, the tray host (such as GNOME's appindicator extension
// or KDE's plasmashell) owns the well-known bus name
// org.kde.StatusNotifierWatcher. A tray application announces itself by
// calling RegisterStatusNotifierItem on that name, and the host then reads
// the application's icon and menu from the application's own bus objects.
//
// This fake claims the org.kde.StatusNotifierWatcher name on our private
// test bus and implements only the RegisterStatusNotifierItem method.
// It returns a channel that receives the object path of each registered
// item, which is how the test observes that the systray app started up far
// enough to announce its tray icon.
func startFakeWatcher(t *testing.T, addr string) <-chan string {
	t.Helper()
	conn, err := dbus.Connect(addr)
	if err != nil {
		t.Fatalf("connecting to session bus: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	// Publish the watcher's methods at the object path that tray apps
	// expect, then claim the well-known bus name so that calls to
	// org.kde.StatusNotifierWatcher are routed to this connection.
	watcher := &fakeNotifierWatcher{registered: make(chan string, 1)}
	if err := conn.Export(watcher, "/StatusNotifierWatcher", "org.kde.StatusNotifierWatcher"); err != nil {
		t.Fatalf("exporting watcher: %v", err)
	}
	reply, err := conn.RequestName("org.kde.StatusNotifierWatcher", dbus.NameFlagDoNotQueue)
	if err != nil || reply != dbus.RequestNameReplyPrimaryOwner {
		t.Fatalf("requesting watcher name: reply=%v err=%v", reply, err)
	}
	return watcher.registered
}

// startFakeLocalAPI serves a fake tailscaled LocalAPI on a unix socket
// and returns the socket path.
//
// The fake reports a running backend with the suggest-exit-node-ui node
// attribute, and suggests an exit node that has no Location. This mirrors
// the tailnet in https://github.com/tailscale/tailscale/issues/20678 where
// building the exit node menu panicked.
func startFakeLocalAPI(t *testing.T, edits *prefsEdits) string {
	t.Helper()

	self := &ipnstate.PeerStatus{
		ID:           "self",
		PublicKey:    key.NewNode().Public(),
		HostName:     "self-host",
		DNSName:      "self-host.example.ts.net.",
		TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.1")},
		Online:       true,
		CapMap: tailcfg.NodeCapMap{
			tailcfg.NodeAttrSuggestExitNodeUI: nil,
		},
	}
	exitNode := &ipnstate.PeerStatus{
		ID:             "exit1",
		PublicKey:      key.NewNode().Public(),
		HostName:       "exit1",
		DNSName:        "exit1.example.ts.net.",
		TailscaleIPs:   []netip.Addr{netip.MustParseAddr("100.64.0.2")},
		Online:         true,
		ExitNodeOption: true,
	}
	status := &ipnstate.Status{
		Version:        "1.0.0-test",
		BackendState:   ipn.Running.String(),
		CurrentTailnet: &ipnstate.TailnetStatus{Name: "example.com"},
		Self:           self,
		Peer: map[key.NodePublic]*ipnstate.PeerStatus{
			exitNode.PublicKey: exitNode,
		},
	}
	profile := ipn.LoginProfile{
		ID:   "profile1",
		Name: "user@example.com",
	}

	serveJSON := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(v)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/localapi/v0/status", func(w http.ResponseWriter, r *http.Request) {
		serveJSON(w, status)
	})
	mux.HandleFunc("/localapi/v0/profiles/current", func(w http.ResponseWriter, r *http.Request) {
		serveJSON(w, profile)
	})
	mux.HandleFunc("/localapi/v0/profiles/", func(w http.ResponseWriter, r *http.Request) {
		serveJSON(w, []ipn.LoginProfile{profile})
	})
	mux.HandleFunc("/localapi/v0/suggest-exit-node", func(w http.ResponseWriter, r *http.Request) {
		// An exit node suggestion with no Location, as returned for
		// regular tailnet exit nodes (as opposed to Mullvad nodes).
		serveJSON(w, apitype.ExitNodeSuggestionResponse{
			ID:   exitNode.ID,
			Name: exitNode.DNSName,
		})
	})
	mux.HandleFunc("/localapi/v0/prefs", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PATCH" {
			var mp ipn.MaskedPrefs
			if err := json.NewDecoder(r.Body).Decode(&mp); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			edits.add(mp)
			serveJSON(w, mp.Prefs)
			return
		}
		// Deliberately asymmetric: a mapping that swapped RouteAll and
		// CorpDNS would still satisfy the labels, but not the checkboxes.
		serveJSON(w, ipn.Prefs{RouteAll: true, CorpDNS: false})
	})
	mux.HandleFunc("/localapi/v0/watch-ipn-bus", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})
	mux.HandleFunc("/localapi/v0/upload-client-metrics", func(w http.ResponseWriter, r *http.Request) {
		serveJSON(w, struct{}{})
	})

	sock := filepath.Join(t.TempDir(), "tailscaled.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return sock
}

// testRunRan tracks whether TestRun has already run in this process.
// The fyne systray package keeps process-global state, so the systray
// application can only be started once per process.
var testRunRan bool

// TestRun starts the systray application against a private dbus session bus
// and a fake LocalAPI, and verifies that it registers a StatusNotifierItem
// and builds its initial menu without crashing.
func TestRun(t *testing.T) {
	if testRunRan {
		t.Skip("the systray app can only run once per process; use -count=1")
	}
	testRunRan = true
	if _, err := exec.LookPath("dbus-daemon"); err != nil {
		if cibuild.On() {
			t.Fatal("dbus-daemon not found in PATH; install the dbus package so CI runs this test")
		}
		t.Skip("dbus-daemon not found in PATH")
	}

	busAddr := startSessionBus(t)
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", busAddr)
	registered := startFakeWatcher(t, busAddr)
	edits := new(prefsEdits)
	sock := startFakeLocalAPI(t, edits)

	// Run the systray app. It has no clean way to shut down (systray.Quit
	// triggers a log.Fatal in the IPN bus watcher), so it is left running
	// until the test process exits.
	menu := new(Menu)
	go menu.Run(&local.Client{Socket: sock, UseSocketOnly: true})

	select {
	case item := <-registered:
		t.Logf("registered StatusNotifierItem: %v", item)
	case <-time.After(30 * time.Second):
		t.Fatal("timed out waiting for StatusNotifierItem registration")
	}

	// Fetch the menu layout. GetLayout blocks server-side until the
	// initial menu has been fully built by onReady.
	conn, err := dbus.Connect(busAddr)
	if err != nil {
		t.Fatalf("connecting to session bus: %v", err)
	}
	defer conn.Close()
	itemName := fmt.Sprintf("org.kde.StatusNotifierItem-%d-1", os.Getpid())

	// Find the menu the way a StatusNotifierHost does, via the item's
	// Menu property, rather than assuming the object path the systray
	// library happens to use (it has changed between releases).
	item := conn.Object(itemName, "/StatusNotifierItem")
	menuPathVar, err := item.GetProperty("org.kde.StatusNotifierItem.Menu")
	if err != nil {
		t.Fatalf("getting Menu property: %v", err)
	}
	menuPath, ok := menuPathVar.Value().(dbus.ObjectPath)
	if !ok {
		t.Fatalf("Menu property is %T, want dbus.ObjectPath", menuPathVar.Value())
	}
	obj := conn.Object(itemName, menuPath)

	// Poll until every expected label shows up. The systray library
	// answers the very first GetLayout with a depth of 1 regardless of
	// what was asked for (and schedules a refresh), so submenu entries
	// like the exit node list only appear on later calls.
	wants := []string{"Connected", "This Device: self-host (100.64.0.1)", "Exit Nodes", "Recommended: exit1", "Accept routes", "Accept DNS", "Quit"}
	var layout string
	var missing []string
	deadline := time.Now().Add(30 * time.Second)
	for {
		call := obj.Call("com.canonical.dbusmenu.GetLayout", 0, int32(0), int32(-1), []string{"label"})
		if call.Err == nil {
			layout = fmt.Sprint(call.Body...)
			missing = missing[:0]
			for _, want := range wants {
				if !strings.Contains(layout, want) {
					missing = append(missing, want)
				}
			}
			if len(missing) == 0 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for menu layout; err=%v missing=%q layout=%v", call.Err, missing, layout)
		}
		time.Sleep(100 * time.Millisecond)
	}

	// The checkboxes must show what the daemon reports, not a default.
	items := menuItemsByLabel(t, obj)
	for label, want := range map[string]int32{"Accept routes": 1, "Accept DNS": 0} {
		item, ok := items[label]
		if !ok {
			t.Errorf("no menu item %q", label)
			continue
		}
		if got := item.toggleState(); got != want {
			t.Errorf("%q toggle-state = %d, want %d", label, got, want)
		}
	}

	// Clicking a checkbox must ask for the opposite of the current value.
	// The fake reports RouteAll true, so the edit must set it false.
	routes, ok := items["Accept routes"]
	if !ok {
		t.Fatal("no \"Accept routes\" menu item to click")
	}
	if call := obj.Call("com.canonical.dbusmenu.Event", 0,
		routes.ID, "clicked", dbus.MakeVariant(""), uint32(time.Now().Unix())); call.Err != nil {
		t.Fatalf("clicking %q: %v", "Accept routes", call.Err)
	}

	deadline = time.Now().Add(30 * time.Second)
	for {
		var got []ipn.MaskedPrefs
		for _, mp := range edits.all() {
			if mp.RouteAllSet {
				got = append(got, mp)
			}
		}
		if len(got) > 0 {
			if got[0].RouteAll {
				t.Errorf("clicking %q asked for RouteAll=true, want false", "Accept routes")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for a RouteAll edit; saw %+v", edits.all())
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// prefsEdits records the preference edits the fake LocalAPI is sent.
type prefsEdits struct {
	mu   sync.Mutex
	seen []ipn.MaskedPrefs
}

func (e *prefsEdits) add(mp ipn.MaskedPrefs) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.seen = append(e.seen, mp)
}

func (e *prefsEdits) all() []ipn.MaskedPrefs {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.seen)
}

// dbusMenuItem is one node of a com.canonical.dbusmenu layout, (ia{sv}av).
type dbusMenuItem struct {
	ID       int32
	Props    map[string]dbus.Variant
	Children []dbus.Variant
}

// menuItemsByLabel returns every labelled menu item, keyed by label.
func menuItemsByLabel(t *testing.T, obj dbus.BusObject) map[string]dbusMenuItem {
	t.Helper()
	call := obj.Call("com.canonical.dbusmenu.GetLayout", 0, int32(0), int32(-1),
		[]string{"label", "toggle-state"})
	if call.Err != nil {
		t.Fatalf("GetLayout: %v", call.Err)
	}
	var revision uint32
	var root dbusMenuItem
	if err := call.Store(&revision, &root); err != nil {
		t.Fatalf("decoding layout: %v", err)
	}

	items := make(map[string]dbusMenuItem)
	var walk func(item dbusMenuItem)
	walk = func(item dbusMenuItem) {
		if label, ok := item.Props["label"]; ok {
			if l, ok := label.Value().(string); ok {
				items[l] = item
			}
		}
		for _, child := range item.Children {
			var c dbusMenuItem
			if err := dbus.Store([]any{child.Value()}, &c); err != nil {
				continue
			}
			walk(c)
		}
	}
	walk(root)
	return items
}

// toggleState returns the item's toggle-state, or -1 when it has none.
func (item dbusMenuItem) toggleState() int32 {
	v, ok := item.Props["toggle-state"]
	if !ok {
		return -1
	}
	s, ok := v.Value().(int32)
	if !ok {
		return -1
	}
	return s
}
