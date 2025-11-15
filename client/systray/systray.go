// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build cgo || !darwin

// Package systray provides a minimal Tailscale systray application.
package systray

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"fyne.io/systray"
	ico "github.com/Kodeworks/golang-image-ico"
	"github.com/atotto/clipboard"
	dbus "github.com/godbus/dbus/v5"
	"github.com/toqueteos/webbrowser"
	"tailscale.com/client/local"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/util/slicesx"
	"tailscale.com/util/stringsx"
)

var (
	// newMenuDelay is the amount of time to sleep after creating a new menu,
	// but before adding items to it. This works around a bug in some dbus implementations.
	newMenuDelay time.Duration

	// if true, treat all mullvad exit node countries as single-city.
	// Instead of rendering a submenu with cities, just select the highest-priority peer.
	hideMullvadCities bool
)

// Run starts the systray menu and blocks until the menu exits.
// If client is nil, a default local.Client is used.
func (menu *Menu) Run(client *local.Client) {
	if client == nil {
		client = &local.Client{}
	}
	menu.lc = client
	menu.updateState()

	// exit cleanly on SIGINT and SIGTERM
	go func() {
		interrupt := make(chan os.Signal, 1)
		signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)
		select {
		case <-interrupt:
			menu.onExit()
		case <-menu.bgCtx.Done():
		}
	}()
	go menu.lc.IncrementGauge(menu.bgCtx, "systray_running", 1)
	defer menu.lc.IncrementGauge(menu.bgCtx, "systray_running", -1)

	systray.Run(menu.onReady, menu.onExit)
}

// Menu represents the systray menu, its items, and the current Tailscale state.
type Menu struct {
	mu sync.Mutex // protects the entire Menu

	lc          *local.Client
	status      *ipnstate.Status
	curProfile  ipn.LoginProfile
	allProfiles []ipn.LoginProfile

	// readonly is whether the systray app is running in read-only mode.
	// This is set if LocalAPI returns a permission error,
	// typically because the user needs to run `tailscale set --operator=$USER`.
	readonly bool

	bgCtx    context.Context // ctx for background tasks not involving menu item clicks
	bgCancel context.CancelFunc

	// Top-level menu items
	connect     *systray.MenuItem
	disconnect  *systray.MenuItem
	self        *systray.MenuItem
	exitNodes   *systray.MenuItem
	more        *systray.MenuItem
	rebuildMenu *systray.MenuItem
	quit        *systray.MenuItem

	rebuildCh  chan struct{} // triggers a menu rebuild
	accountsCh chan ipn.ProfileID
	exitNodeCh chan tailcfg.StableNodeID // ID of selected exit node

	eventCancel context.CancelFunc // cancel eventLoop

	notificationIcon *os.File // icon used for desktop notifications
}

func (menu *Menu) init() {
	if menu.bgCtx != nil {
		// already initialized
		return
	}

	menu.rebuildCh = make(chan struct{}, 1)
	menu.accountsCh = make(chan ipn.ProfileID)
	menu.exitNodeCh = make(chan tailcfg.StableNodeID)

	// dbus wants a file path for notification icons, so copy to a temp file.
	menu.notificationIcon, _ = os.CreateTemp("", "tailscale-systray.png")
	io.Copy(menu.notificationIcon, connected.renderWithBorder(3))

	menu.bgCtx, menu.bgCancel = context.WithCancel(context.Background())
	go menu.watchIPNBus()
}

func init() {
	if runtime.GOOS != "linux" {
		// so far, these tweaks are only needed on Linux
		return
	}

	desktop := strings.ToLower(os.Getenv("XDG_CURRENT_DESKTOP"))
	switch desktop {
	case "gnome", "ubuntu:gnome":
		// GNOME expands submenus downward in the main menu, rather than flyouts to the side.
		// Either as a result of that or another limitation, there seems to be a maximum depth of submenus.
		// Mullvad countries that have a city submenu are not being rendered, and so can't be selected.
		// Handle this by simply treating all mullvad countries as single-city and select the best peer.
		hideMullvadCities = true
	case "kde":
		// KDE doesn't need a delay, and actually won't render submenus
		// if we delay for more than about 400µs.
		newMenuDelay = 0
	default:
		// Add a slight delay to ensure the menu is created before adding items.
		//
		// Systray implementations that use libdbusmenu sometimes process messages out of order,
		// resulting in errors such as:
		//    (waybar:153009): LIBDBUSMENU-GTK-WARNING **: 18:07:11.551: Children but no menu, someone's been naughty with their 'children-display' property: 'submenu'
		//
		// See also: https://github.com/fyne-io/systray/issues/12
		newMenuDelay = 10 * time.Millisecond
	}
}

// onReady is called by the systray package when the menu is ready to be built.
func (menu *Menu) onReady() {
	log.Printf("starting")
	if os.Getuid() == 0 || os.Getuid() != os.Geteuid() || os.Getenv("SUDO_USER") != "" || os.Getenv("DOAS_USER") != "" {
		fmt.Fprintln(os.Stderr, `
It appears that you might be running the systray with sudo/doas.
This can lead to issues with D-Bus, and should be avoided.

The systray application should be run with the same user as your desktop session.
This usually means that you should run the application like:

tailscale systray

See https://tailscale.com/kb/1597/linux-systray for more information.`)
	}
	setAppIcon(disconnected)
	menu.rebuild()

	menu.mu.Lock()
	if menu.readonly {
		fmt.Fprintln(os.Stderr, `
No permission to manage Tailscale. Set operator by running:

sudo tailscale set --operator=$USER

See https://tailscale.com/s/cli-operator for more information.`)
	}
	menu.mu.Unlock()
}

// updateState updates the Menu state from the Tailscale local client.
func (menu *Menu) updateState() {
	menu.mu.Lock()
	defer menu.mu.Unlock()
	menu.init()

	menu.readonly = false

	var err error
	menu.status, err = menu.lc.Status(menu.bgCtx)
	if err != nil {
		log.Print(err)
	}
	menu.curProfile, menu.allProfiles, err = menu.lc.ProfileStatus(menu.bgCtx)
	if err != nil {
		if local.IsAccessDeniedError(err) {
			menu.readonly = true
		}
		log.Print(err)
	}
}

// rebuild the systray menu based on the current Tailscale state.
//
// We currently rebuild the entire menu because it is not easy to update the existing menu.
// You cannot iterate over the items in a menu, nor can you remove some items like separators.
// So for now we rebuild the whole thing, and can optimize this later if needed.
func (menu *Menu) rebuild() {
	menu.mu.Lock()
	defer menu.mu.Unlock()
	menu.init()

	if menu.eventCancel != nil {
		menu.eventCancel()
	}
	ctx := context.Background()
	ctx, menu.eventCancel = context.WithCancel(ctx)

	systray.ResetMenu()

	if menu.readonly {
		const readonlyMsg = "No permission to manage Tailscale.\nSee tailscale.com/s/cli-operator"
		m := systray.AddMenuItem(readonlyMsg, "")
		onClick(ctx, m, func(_ context.Context) {
			webbrowser.Open("https://tailscale.com/s/cli-operator")
		})
		systray.AddSeparator()
	}

	menu.connect = systray.AddMenuItem("Connect", "")
	menu.disconnect = systray.AddMenuItem("Disconnect", "")
	menu.disconnect.Hide()
	systray.AddSeparator()

	// delay to prevent race setting icon on first start
	time.Sleep(newMenuDelay)

	// Set systray menu icon and title.
	// Also adjust connect/disconnect menu items if needed.
	var backendState string
	if menu.status != nil {
		backendState = menu.status.BackendState
	}
	switch backendState {
	case ipn.Running.String():
		if menu.status.ExitNodeStatus != nil && !menu.status.ExitNodeStatus.ID.IsZero() {
			if menu.status.ExitNodeStatus.Online {
				setTooltip("Using exit node")
				setAppIcon(exitNodeOnline)
			} else {
				setTooltip("Exit node offline")
				setAppIcon(exitNodeOffline)
			}
		} else {
			setTooltip(fmt.Sprintf("Connected to %s", menu.status.CurrentTailnet.Name))
			setAppIcon(connected)
		}
		menu.connect.SetTitle("Connected")
		menu.connect.Disable()
		menu.disconnect.Show()
		menu.disconnect.Enable()
	case ipn.Starting.String():
		setTooltip("Connecting")
		setAppIcon(loading)
	default:
		setTooltip("Disconnected")
		setAppIcon(disconnected)
	}

	if menu.readonly {
		menu.connect.Disable()
		menu.disconnect.Disable()
	}

	account := "Account"
	if pt := profileTitle(menu.curProfile); pt != "" {
		account = pt
	}
	if !menu.readonly {
		accounts := systray.AddMenuItem(account, "")
		setRemoteIcon(accounts, menu.curProfile.UserProfile.ProfilePicURL)
		time.Sleep(newMenuDelay)
		for _, profile := range menu.allProfiles {
			title := profileTitle(profile)
			var item *systray.MenuItem
			if profile.ID == menu.curProfile.ID {
				item = accounts.AddSubMenuItemCheckbox(title, "", true)
			} else {
				item = accounts.AddSubMenuItem(title, "")
			}
			setRemoteIcon(item, profile.UserProfile.ProfilePicURL)
			onClick(ctx, item, func(ctx context.Context) {
				select {
				case <-ctx.Done():
				case menu.accountsCh <- profile.ID:
				}
			})
		}
	}

	if menu.status != nil && menu.status.Self != nil && len(menu.status.Self.TailscaleIPs) > 0 {
		title := fmt.Sprintf("This Device: %s (%s)", menu.status.Self.HostName, menu.status.Self.TailscaleIPs[0])
		menu.self = systray.AddMenuItem(title, "")
	} else {
		menu.self = systray.AddMenuItem("This Device: not connected", "")
		menu.self.Disable()
	}
	systray.AddSeparator()

	if !menu.readonly {
		menu.rebuildExitNodeMenu(ctx)
	}

	menu.more = systray.AddMenuItem("More settings", "")
	if menu.status != nil && menu.status.BackendState == "Running" {
		// web client is only available if backend is running
		onClick(ctx, menu.more, func(_ context.Context) {
			webbrowser.Open("http://100.100.100.100/")
		})
	} else {
		menu.more.Disable()
	}

	// TODO(#15528): this menu item shouldn't be necessary at all,
	// but is at least more discoverable than having users switch profiles or exit nodes.
	menu.rebuildMenu = systray.AddMenuItem("Rebuild menu", "Fix missing menu items")
	onClick(ctx, menu.rebuildMenu, func(ctx context.Context) {
		select {
		case <-ctx.Done():
		case menu.rebuildCh <- struct{}{}:
		}
	})
	menu.rebuildMenu.Enable()

	menu.quit = systray.AddMenuItem("Quit", "Quit the app")
	menu.quit.Enable()

	go menu.eventLoop(ctx)
}

// profileTitle returns the title string for a profile menu item.
func profileTitle(profile ipn.LoginProfile) string {
	title := profile.Name
	if profile.NetworkProfile.DomainName != "" {
		if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
			// windows and mac don't support multi-line menu
			title += " (" + profile.NetworkProfile.DisplayNameOrDefault() + ")"
		} else {
			title += "\n" + profile.NetworkProfile.DisplayNameOrDefault()
		}
	}
	return title
}

var (
	cacheMu   sync.Mutex
	httpCache = map[string][]byte{} // URL => response body
)

// setRemoteIcon sets the icon for menu to the specified remote image.
// Remote images are fetched as needed and cached.
func setRemoteIcon(menu *systray.MenuItem, urlStr string) {
	if menu == nil || urlStr == "" {
		return
	}

	cacheMu.Lock()
	b, ok := httpCache[urlStr]
	if !ok {
		resp, err := http.Get(urlStr)
		if err == nil && resp.StatusCode == http.StatusOK {
			b, _ = io.ReadAll(resp.Body)

			// Convert image to ICO format on Windows
			if runtime.GOOS == "windows" {
				im, _, err := image.Decode(bytes.NewReader(b))
				if err != nil {
					return
				}
				buf := bytes.NewBuffer(nil)
				if err := ico.Encode(buf, im); err != nil {
					return
				}
				b = buf.Bytes()
			}

			httpCache[urlStr] = b
			resp.Body.Close()
		}
	}
	cacheMu.Unlock()

	if len(b) > 0 {
		menu.SetIcon(b)
	}
}

// setTooltip sets the tooltip text for the systray icon.
func setTooltip(text string) {
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		systray.SetTooltip(text)
	} else {
		// on Linux, SetTitle actually sets the tooltip
		systray.SetTitle(text)
	}
}

// eventLoop is the main event loop for handling click events on menu items
// and responding to Tailscale state changes.
// This method does not return until ctx.Done is closed.
func (menu *Menu) eventLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-menu.rebuildCh:
			menu.updateState()
			menu.rebuild()
		case <-menu.connect.ClickedCh:
			_, err := menu.lc.EditPrefs(ctx, &ipn.MaskedPrefs{
				Prefs: ipn.Prefs{
					WantRunning: true,
				},
				WantRunningSet: true,
			})
			if err != nil {
				log.Printf("error connecting: %v", err)
			}

		case <-menu.disconnect.ClickedCh:
			_, err := menu.lc.EditPrefs(ctx, &ipn.MaskedPrefs{
				Prefs: ipn.Prefs{
					WantRunning: false,
				},
				WantRunningSet: true,
			})
			if err != nil {
				log.Printf("error disconnecting: %v", err)
			}

		case <-menu.self.ClickedCh:
			menu.copyTailscaleIP(menu.status.Self)

		case id := <-menu.accountsCh:
			if err := menu.lc.SwitchProfile(ctx, id); err != nil {
				log.Printf("error switching to profile ID %v: %v", id, err)
			}

		case exitNode := <-menu.exitNodeCh:
			if exitNode.IsZero() {
				log.Print("disable exit node")
				if err := menu.lc.SetUseExitNode(ctx, false); err != nil {
					log.Printf("error disabling exit node: %v", err)
				}
			} else {
				log.Printf("enable exit node: %v", exitNode)
				mp := &ipn.MaskedPrefs{
					Prefs: ipn.Prefs{
						ExitNodeID: exitNode,
					},
					ExitNodeIDSet: true,
				}
				if _, err := menu.lc.EditPrefs(ctx, mp); err != nil {
					log.Printf("error setting exit node: %v", err)
				}
			}

		case <-menu.quit.ClickedCh:
			systray.Quit()
		}
	}
}

// onClick registers a click handler for a menu item.
func onClick(ctx context.Context, item *systray.MenuItem, fn func(ctx context.Context)) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-item.ClickedCh:
				fn(ctx)
			}
		}
	}()
}

// watchIPNBus subscribes to the tailscale event bus and sends state updates to chState.
// This method does not return.
func (menu *Menu) watchIPNBus() {
	for {
		if err := menu.watchIPNBusInner(); err != nil {
			log.Println(err)
			if errors.Is(err, context.Canceled) {
				// If the context got canceled, we will never be able to
				// reconnect to IPN bus, so exit the process.
				log.Fatalf("watchIPNBus: %v", err)
			}
		}
		// If our watch connection breaks, wait a bit before reconnecting. No
		// reason to spam the logs if e.g. tailscaled is restarting or goes
		// down.
		time.Sleep(3 * time.Second)
	}
}

func (menu *Menu) watchIPNBusInner() error {
	watcher, err := menu.lc.WatchIPNBus(menu.bgCtx, 0)
	if err != nil {
		return fmt.Errorf("watching ipn bus: %w", err)
	}
	defer watcher.Close()
	for {
		select {
		case <-menu.bgCtx.Done():
			return nil
		default:
			n, err := watcher.Next()
			if err != nil {
				return fmt.Errorf("ipnbus error: %w", err)
			}
			var rebuild bool
			if n.State != nil {
				log.Printf("new state: %v", n.State)
				rebuild = true
			}
			if n.Prefs != nil {
				rebuild = true
			}
			if rebuild {
				menu.rebuildCh <- struct{}{}
			}
		}
	}
}

// copyTailscaleIP copies the first Tailscale IP of the given device to the clipboard
// and sends a notification with the copied value.
func (menu *Menu) copyTailscaleIP(device *ipnstate.PeerStatus) {
	if device == nil || len(device.TailscaleIPs) == 0 {
		return
	}
	name := strings.Split(device.DNSName, ".")[0]
	ip := device.TailscaleIPs[0].String()
	err := clipboard.WriteAll(ip)
	if err != nil {
		log.Printf("clipboard error: %v", err)
	} else {
		menu.sendNotification(fmt.Sprintf("Copied Address for %v", name), ip)
	}
}

// sendNotification sends a desktop notification with the given title and content.
func (menu *Menu) sendNotification(title, content string) {
	conn, err := dbus.SessionBus()
	if err != nil {
		log.Printf("dbus: %v", err)
		return
	}
	timeout := 3 * time.Second
	obj := conn.Object("org.freedesktop.Notifications", "/org/freedesktop/Notifications")
	call := obj.Call("org.freedesktop.Notifications.Notify", 0, "Tailscale", uint32(0),
		menu.notificationIcon.Name(), title, content, []string{}, map[string]dbus.Variant{}, int32(timeout.Milliseconds()))
	if call.Err != nil {
		log.Printf("dbus: %v", call.Err)
	}
}

func (menu *Menu) rebuildExitNodeMenu(ctx context.Context) {
	if menu.status == nil {
		return
	}

	status := menu.status
	menu.exitNodes = systray.AddMenuItem("Exit Nodes", "")
	time.Sleep(newMenuDelay)

	// register a click handler for a menu item to set nodeID as the exit node.
	setExitNodeOnClick := func(item *systray.MenuItem, nodeID tailcfg.StableNodeID) {
		onClick(ctx, item, func(ctx context.Context) {
			select {
			case <-ctx.Done():
			case menu.exitNodeCh <- nodeID:
			}
		})
	}

	noExitNodeMenu := menu.exitNodes.AddSubMenuItemCheckbox("None", "", status.ExitNodeStatus == nil)
	setExitNodeOnClick(noExitNodeMenu, "")

	// Show recommended exit node if available.
	if status.Self.CapMap.Contains(tailcfg.NodeAttrSuggestExitNodeUI) {
		sugg, err := menu.lc.SuggestExitNode(ctx)
		if err == nil {
			title := "Recommended: "
			if loc := sugg.Location; loc.Valid() && loc.Country() != "" {
				flag := countryFlag(loc.CountryCode())
				title += fmt.Sprintf("%s %s: %s", flag, loc.Country(), loc.City())
			} else {
				title += strings.Split(sugg.Name, ".")[0]
			}
			menu.exitNodes.AddSeparator()
			rm := menu.exitNodes.AddSubMenuItemCheckbox(title, "", false)
			setExitNodeOnClick(rm, sugg.ID)
			if status.ExitNodeStatus != nil && sugg.ID == status.ExitNodeStatus.ID {
				rm.Check()
			}
		}
	}

	// Add tailnet exit nodes if present.
	var tailnetExitNodes []*ipnstate.PeerStatus
	for _, ps := range status.Peer {
		if ps.ExitNodeOption && ps.Location == nil {
			tailnetExitNodes = append(tailnetExitNodes, ps)
		}
	}
	if len(tailnetExitNodes) > 0 {
		menu.exitNodes.AddSeparator()
		menu.exitNodes.AddSubMenuItem("Tailnet Exit Nodes", "").Disable()
		for _, ps := range status.Peer {
			if !ps.ExitNodeOption || ps.Location != nil {
				continue
			}
			name := strings.Split(ps.DNSName, ".")[0]
			if !ps.Online {
				name += " (offline)"
			}
			sm := menu.exitNodes.AddSubMenuItemCheckbox(name, "", false)
			if !ps.Online {
				sm.Disable()
			}
			if status.ExitNodeStatus != nil && ps.ID == status.ExitNodeStatus.ID {
				sm.Check()
			}
			setExitNodeOnClick(sm, ps.ID)
		}
	}

	// Add mullvad exit nodes if present.
	var mullvadExitNodes mullvadPeers
	if status.Self.CapMap.Contains("mullvad") {
		mullvadExitNodes = newMullvadPeers(status)
	}
	if len(mullvadExitNodes.countries) > 0 {
		menu.exitNodes.AddSeparator()
		menu.exitNodes.AddSubMenuItem("Location-based Exit Nodes", "").Disable()
		mullvadMenu := menu.exitNodes.AddSubMenuItemCheckbox("Mullvad VPN", "", false)

		for _, country := range mullvadExitNodes.sortedCountries() {
			flag := countryFlag(country.code)
			countryMenu := mullvadMenu.AddSubMenuItemCheckbox(flag+" "+country.name, "", false)

			// single-city country, no submenu
			if len(country.cities) == 1 || hideMullvadCities {
				setExitNodeOnClick(countryMenu, country.best.ID)
				if status.ExitNodeStatus != nil {
					for _, city := range country.cities {
						for _, ps := range city.peers {
							if status.ExitNodeStatus.ID == ps.ID {
								mullvadMenu.Check()
								countryMenu.Check()
							}
						}
					}
				}
				continue
			}

			// multi-city country, build submenu with "best available" option and cities.
			time.Sleep(newMenuDelay)
			bm := countryMenu.AddSubMenuItemCheckbox("Best Available", "", false)
			setExitNodeOnClick(bm, country.best.ID)
			countryMenu.AddSeparator()

			for _, city := range country.sortedCities() {
				cityMenu := countryMenu.AddSubMenuItemCheckbox(city.name, "", false)
				setExitNodeOnClick(cityMenu, city.best.ID)
				if status.ExitNodeStatus != nil {
					for _, ps := range city.peers {
						if status.ExitNodeStatus.ID == ps.ID {
							mullvadMenu.Check()
							countryMenu.Check()
							cityMenu.Check()
						}
					}
				}
			}
		}
	}

	// TODO: "Allow Local Network Access" and "Run Exit Node" menu items
}

// mullvadPeers contains all mullvad peer nodes, sorted by country and city.
type mullvadPeers struct {
	countries map[string]*mvCountry // country code (uppercase) => country
}

// sortedCountries returns countries containing mullvad nodes, sorted by name.
func (mp mullvadPeers) sortedCountries() []*mvCountry {
	countries := slicesx.MapValues(mp.countries)
	slices.SortFunc(countries, func(a, b *mvCountry) int {
		return stringsx.CompareFold(a.name, b.name)
	})
	return countries
}

type mvCountry struct {
	code   string
	name   string
	best   *ipnstate.PeerStatus // highest priority peer in the country
	cities map[string]*mvCity   // city code => city
}

// sortedCities returns cities containing mullvad nodes, sorted by name.
func (mc *mvCountry) sortedCities() []*mvCity {
	cities := slicesx.MapValues(mc.cities)
	slices.SortFunc(cities, func(a, b *mvCity) int {
		return stringsx.CompareFold(a.name, b.name)
	})
	return cities
}

// countryFlag takes a 2-character ASCII string and returns the corresponding emoji flag.
// It returns the empty string on error.
func countryFlag(code string) string {
	if len(code) != 2 {
		return ""
	}
	runes := make([]rune, 0, 2)
	for i := range 2 {
		b := code[i] | 32 // lowercase
		if b < 'a' || b > 'z' {
			return ""
		}
		// https://en.wikipedia.org/wiki/Regional_indicator_symbol
		runes = append(runes, 0x1F1E6+rune(b-'a'))
	}
	return string(runes)
}

type mvCity struct {
	name  string
	best  *ipnstate.PeerStatus // highest priority peer in the city
	peers []*ipnstate.PeerStatus
}

func newMullvadPeers(status *ipnstate.Status) mullvadPeers {
	countries := make(map[string]*mvCountry)
	for _, ps := range status.Peer {
		if !ps.ExitNodeOption || ps.Location == nil {
			continue
		}
		loc := ps.Location
		country, ok := countries[loc.CountryCode]
		if !ok {
			country = &mvCountry{
				code:   loc.CountryCode,
				name:   loc.Country,
				cities: make(map[string]*mvCity),
			}
			countries[loc.CountryCode] = country
		}
		city, ok := countries[loc.CountryCode].cities[loc.CityCode]
		if !ok {
			city = &mvCity{
				name: loc.City,
			}
			countries[loc.CountryCode].cities[loc.CityCode] = city
		}
		city.peers = append(city.peers, ps)
		if city.best == nil || ps.Location.Priority > city.best.Location.Priority {
			city.best = ps
		}
		if country.best == nil || ps.Location.Priority > country.best.Location.Priority {
			country.best = ps
		}
	}
	return mullvadPeers{countries}
}

// onExit is called by the systray package when the menu is exiting.
func (menu *Menu) onExit() {
	log.Printf("exiting")
	if menu.bgCancel != nil {
		menu.bgCancel()
	}
	if menu.eventCancel != nil {
		menu.eventCancel()
	}

	os.Remove(menu.notificationIcon.Name())
}
