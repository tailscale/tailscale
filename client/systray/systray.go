// Copyright (c) Tailscale Inc & contributors
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

	// Set the initial icon before systray.Run so the StatusNotifierItem
	// exports a non-empty image on startup.
	setAppIcon(&disconnected)

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
	go menu.lc.SetGauge(menu.bgCtx, "systray_running", 1)
	defer menu.lc.SetGauge(menu.bgCtx, "systray_running", 0)

	systray.Run(menu.onReady, menu.onExit)
}

// Menu represents the systray menu, its items, and the current Tailscale state.
type Menu struct {
	mu sync.Mutex // protects the entire Menu

	lc          *local.Client
	status      *ipnstate.Status
	prefs       *ipn.Prefs
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

	// lastShape is the menuShape from the most recent build.
	lastShape menuShape

	// Cached last-applied values used to short-circuit redundant updates.
	connectTitle      string
	selfTitle         string
	disconnectVisible bool
	lastTooltip       string
	lastIcon          *tsLogo

	// Per-row tracking, populated by buildMenu and reset on each rebuild.
	accountItems          map[ipn.ProfileID]*systray.MenuItem
	noExitNodeItem        *systray.MenuItem
	recommendedExitItem   *systray.MenuItem
	recommendedExitNodeID tailcfg.StableNodeID
	tailnetExitItems      map[tailcfg.StableNodeID]*systray.MenuItem
	mullvadCountryItems   map[string]*systray.MenuItem // CC -> item (single-city only)
	mullvadCityItems      map[string]*systray.MenuItem // "<CC>/<CityCode>" -> item

	rebuildCh    chan struct{} // triggers a menu refresh (build if shape changed)
	forceBuildCh chan struct{} // forces a full buildMenu (escape hatch)
	accountsCh   chan ipn.ProfileID
	exitNodeCh   chan tailcfg.StableNodeID // ID of selected exit node

	eventCancel context.CancelFunc // cancel eventLoop

	notificationIcon *os.File // icon used for desktop notifications
}

func (menu *Menu) init() {
	if menu.bgCtx != nil {
		// already initialized
		return
	}

	menu.rebuildCh = make(chan struct{}, 1)
	menu.forceBuildCh = make(chan struct{}, 1)
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
	setAppIcon(&disconnected)

	// set initial title, which is used by the systray package as the ID of the StatusNotifierItem.
	// This value will get overwritten later as the client status changes.
	systray.SetTitle("tailscale")

	menu.buildMenu()

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
	menu.prefs, err = menu.lc.GetPrefs(menu.bgCtx)
	if err != nil {
		if local.IsAccessDeniedError(err) {
			menu.readonly = true
		}
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

// activeExitNodeID returns the user's selected exit node, preferring
// prefs over status so a configured-but-unreachable exit node still
// reports as selected.
func activeExitNodeID(prefs *ipn.Prefs, status *ipnstate.Status) tailcfg.StableNodeID {
	if prefs != nil && !prefs.ExitNodeID.IsZero() {
		return prefs.ExitNodeID
	}
	if status != nil && status.ExitNodeStatus != nil {
		return status.ExitNodeStatus.ID
	}
	return ""
}

// appearance returns the systray icon and tooltip for the given state.
func appearance(status *ipnstate.Status, prefs *ipn.Prefs) (*tsLogo, string) {
	if status == nil {
		return &disconnected, "Disconnected"
	}
	switch status.BackendState {
	case ipn.Running.String():
		if !activeExitNodeID(prefs, status).IsZero() {
			if status.ExitNodeStatus != nil && status.ExitNodeStatus.Online {
				return &exitNodeOnline, "Using exit node"
			}
			return &exitNodeOffline, "Exit node offline"
		}
		return &connected, fmt.Sprintf("Connected to %s", status.CurrentTailnet.Name)
	case ipn.Starting.String():
		return &loading, "Connecting"
	}
	return &disconnected, "Disconnected"
}

// setEnabled and setChecked skip the underlying call when the item is
// already in the desired state, to avoid redundant menu update signals.
func setEnabled(item *systray.MenuItem, enabled bool) {
	if item == nil || item.Disabled() == !enabled {
		return
	}

	if enabled {
		item.Enable()
	} else {
		item.Disable()
	}
}

func setChecked(item *systray.MenuItem, checked bool) {
	if item == nil || item.Checked() == checked {
		return
	}

	if checked {
		item.Check()
	} else {
		item.Uncheck()
	}
}

// setTitleIfChanged updates item's title only when it differs from the
// cached value.
func setTitleIfChanged(cache *string, item *systray.MenuItem, title string) {
	if item == nil || *cache == title {
		return
	}

	*cache = title
	item.SetTitle(title)
}

// setVisibleIfChanged toggles item visibility only when it differs from
// the cached value.
func setVisibleIfChanged(cache *bool, item *systray.MenuItem, visible bool) {
	if item == nil || *cache == visible {
		return
	}

	*cache = visible
	if visible {
		item.Show()
	} else {
		item.Hide()
	}
}

// setTooltipIfChanged forwards to setTooltip only when the text differs
// from the last call.
func (menu *Menu) setTooltipIfChanged(text string) {
	if menu.lastTooltip == text {
		return
	}
	menu.lastTooltip = text
	setTooltip(text)
}

// setAppIconIfChanged forwards to setAppIcon only when icon differs from
// the last call.
func (menu *Menu) setAppIconIfChanged(icon *tsLogo) {
	if menu.lastIcon == icon {
		return
	}
	menu.lastIcon = icon
	setAppIcon(icon)
}

// menuShape captures everything that, if changed, requires a full rebuild of
// the menu rather than an in-place property refresh.
type menuShape struct {
	readonly       bool
	backendKnown   bool
	curProfileID   ipn.ProfileID
	profileIDs     string // sorted, comma-joined ProfileIDs
	tailnetExitIDs string // sorted, comma-joined StableNodeIDs of tailnet exit nodes
	mullvadEnabled bool
	mullvadKey     string // sorted, comma-joined "<CC>/<CityCode>" pairs
}

// computeShape derives a menuShape from the given inputs.
func computeShape(status *ipnstate.Status, curProfile ipn.LoginProfile, allProfiles []ipn.LoginProfile, readonly bool) menuShape {
	s := menuShape{
		readonly:     readonly,
		backendKnown: status != nil,
		curProfileID: curProfile.ID,
	}

	ids := make([]string, 0, len(allProfiles))
	for _, p := range allProfiles {
		ids = append(ids, string(p.ID))
	}
	slices.Sort(ids)
	s.profileIDs = strings.Join(ids, ",")

	if status == nil {
		return s
	}

	var tailnetIDs []string
	var mullvadPairs []string
	mullvadEligible := status.Self != nil && status.Self.CapMap.Contains("mullvad")
	for _, ps := range status.Peer {
		if !ps.ExitNodeOption {
			continue
		}
		if ps.Location == nil {
			tailnetIDs = append(tailnetIDs, string(ps.ID))
			continue
		}
		if mullvadEligible {
			mullvadPairs = append(mullvadPairs, ps.Location.CountryCode+"/"+ps.Location.CityCode)
		}
	}
	slices.Sort(tailnetIDs)
	s.tailnetExitIDs = strings.Join(tailnetIDs, ",")
	s.mullvadEnabled = mullvadEligible && len(mullvadPairs) > 0
	if s.mullvadEnabled {
		slices.Sort(mullvadPairs)
		mullvadPairs = slices.Compact(mullvadPairs)
		s.mullvadKey = strings.Join(mullvadPairs, ",")
	}
	return s
}

// refreshMenu reflects the current Tailscale state into the menu. If the
// structural shape of the inputs hasn't changed, it mutates existing items
// in place; otherwise it falls back to a full buildMenu.
func (menu *Menu) refreshMenu() {
	menu.mu.Lock()
	defer menu.mu.Unlock()
	menu.init()

	shape := computeShape(menu.status, menu.curProfile, menu.allProfiles, menu.readonly)
	if menu.connect == nil || shape != menu.lastShape {
		menu.buildMenuLocked()
		return
	}

	icon, tooltip := appearance(menu.status, menu.prefs)
	menu.setTooltipIfChanged(tooltip)
	menu.setAppIconIfChanged(icon)

	running := menu.status != nil && menu.status.BackendState == ipn.Running.String()
	if running {
		setTitleIfChanged(&menu.connectTitle, menu.connect, "Connected")
		setEnabled(menu.connect, false)
		setVisibleIfChanged(&menu.disconnectVisible, menu.disconnect, true)
		setEnabled(menu.disconnect, !menu.readonly)
	} else {
		setTitleIfChanged(&menu.connectTitle, menu.connect, "Connect")
		setEnabled(menu.connect, !menu.readonly)
		setVisibleIfChanged(&menu.disconnectVisible, menu.disconnect, false)
	}
	setEnabled(menu.more, running)

	if menu.status != nil && menu.status.Self != nil && len(menu.status.Self.TailscaleIPs) > 0 {
		setTitleIfChanged(&menu.selfTitle, menu.self, fmt.Sprintf("This Device: %s (%s)",
			menu.status.Self.HostName, menu.status.Self.TailscaleIPs[0]))
		setEnabled(menu.self, true)
	} else {
		setTitleIfChanged(&menu.selfTitle, menu.self, "This Device: not connected")
		setEnabled(menu.self, false)
	}

	for id, item := range menu.accountItems {
		setChecked(item, id == menu.curProfile.ID)
	}

	sel := activeExitNodeID(menu.prefs, menu.status)
	setChecked(menu.noExitNodeItem, sel == "")
	setChecked(menu.recommendedExitItem, sel != "" && sel == menu.recommendedExitNodeID)

	var mvCountry, mvCity string
	if menu.status != nil {
		for _, ps := range menu.status.Peer {
			if !ps.ExitNodeOption {
				continue
			}
			if ps.Location == nil {
				if item, ok := menu.tailnetExitItems[ps.ID]; ok {
					setChecked(item, ps.ID == sel)
					setEnabled(item, ps.Online)
				}
				continue
			}
			if sel != "" && ps.ID == sel {
				mvCountry = ps.Location.CountryCode
				mvCity = mvCountry + "/" + ps.Location.CityCode
			}
		}
	}
	for cc, item := range menu.mullvadCountryItems {
		setChecked(item, cc == mvCountry)
	}
	for k, item := range menu.mullvadCityItems {
		setChecked(item, k == mvCity)
	}
}

// buildMenu rebuilds the menu from scratch. Prefer refreshMenu when only
// properties have changed.
func (menu *Menu) buildMenu() {
	menu.mu.Lock()
	defer menu.mu.Unlock()
	menu.buildMenuLocked()
}

// buildMenuLocked is buildMenu with menu.mu already held.
func (menu *Menu) buildMenuLocked() {
	menu.init()

	if menu.eventCancel != nil {
		menu.eventCancel()
	}
	ctx := context.Background()
	ctx, menu.eventCancel = context.WithCancel(ctx)

	// Reset trackers and caches; ResetMenu invalidates the previous
	// build's item pointers.
	menu.accountItems = map[ipn.ProfileID]*systray.MenuItem{}
	menu.tailnetExitItems = map[tailcfg.StableNodeID]*systray.MenuItem{}
	menu.mullvadCountryItems = map[string]*systray.MenuItem{}
	menu.mullvadCityItems = map[string]*systray.MenuItem{}
	menu.noExitNodeItem = nil
	menu.recommendedExitItem = nil
	menu.recommendedExitNodeID = ""
	menu.connectTitle = ""
	menu.selfTitle = ""
	menu.disconnectVisible = false
	menu.lastTooltip = ""
	menu.lastIcon = nil

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

	icon, tooltip := appearance(menu.status, menu.prefs)
	menu.setTooltipIfChanged(tooltip)
	menu.setAppIconIfChanged(icon)

	if menu.status != nil && menu.status.BackendState == ipn.Running.String() {
		setTitleIfChanged(&menu.connectTitle, menu.connect, "Connected")
		menu.connect.Disable()
		setVisibleIfChanged(&menu.disconnectVisible, menu.disconnect, true)
		setEnabled(menu.disconnect, !menu.readonly)
	} else if menu.readonly {
		menu.connect.Disable()
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
				item = accounts.AddSubMenuItemCheckbox(title, "", false)
			}
			menu.accountItems[profile.ID] = item
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
		// Force a full rebuild; refresh would be a no-op when the
		// structural shape is unchanged.
		select {
		case <-ctx.Done():
		case menu.forceBuildCh <- struct{}{}:
		default:
		}
	})
	menu.rebuildMenu.Enable()

	menu.quit = systray.AddMenuItem("Quit", "Quit the app")
	menu.quit.Enable()

	menu.lastShape = computeShape(menu.status, menu.curProfile, menu.allProfiles, menu.readonly)

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
	defer cacheMu.Unlock()
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

// eventLoop dispatches menu clicks and bus-driven refreshes until ctx is
// canceled. Daemon API calls use menu.bgCtx so user actions aren't lost
// when ctx is canceled by a concurrent rebuild.
func (menu *Menu) eventLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-menu.rebuildCh:
			menu.updateState()
			menu.refreshMenu()
		case <-menu.forceBuildCh:
			menu.updateState()
			menu.buildMenu()
		case <-menu.connect.ClickedCh:
			_, err := menu.lc.EditPrefs(menu.bgCtx, &ipn.MaskedPrefs{
				Prefs: ipn.Prefs{
					WantRunning: true,
				},
				WantRunningSet: true,
			})
			if err != nil {
				log.Printf("error connecting: %v", err)
			}

		case <-menu.disconnect.ClickedCh:
			_, err := menu.lc.EditPrefs(menu.bgCtx, &ipn.MaskedPrefs{
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
			if err := menu.lc.SwitchProfile(menu.bgCtx, id); err != nil {
				log.Printf("error switching to profile ID %v: %v", id, err)
			}

		case exitNode := <-menu.exitNodeCh:
			if exitNode.IsZero() {
				log.Print("disable exit node")
				if err := menu.lc.SetUseExitNode(menu.bgCtx, false); err != nil {
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
				if _, err := menu.lc.EditPrefs(menu.bgCtx, mp); err != nil {
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
			if url := n.BrowseToURL; url != nil {
				// Avoid opening the browser when running as root, just in case.
				runningAsRoot := os.Getuid() == 0
				if !runningAsRoot {
					if err := webbrowser.Open(*url); err != nil {
						log.Printf("failed to open BrowseToURL: %v", err)
					}
				}
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
				// Refreshes are level-triggered; a queued request already
				// covers any further events.
				select {
				case menu.rebuildCh <- struct{}{}:
				default:
				}
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

	sel := activeExitNodeID(menu.prefs, status)

	noExitNodeMenu := menu.exitNodes.AddSubMenuItemCheckbox("None", "", sel == "")
	menu.noExitNodeItem = noExitNodeMenu
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
			rm := menu.exitNodes.AddSubMenuItemCheckbox(title, "", sel != "" && sugg.ID == sel)
			menu.recommendedExitItem = rm
			menu.recommendedExitNodeID = sugg.ID
			setExitNodeOnClick(rm, sugg.ID)
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
			sm := menu.exitNodes.AddSubMenuItemCheckbox(name, "", ps.ID == sel)
			menu.tailnetExitItems[ps.ID] = sm
			if !ps.Online {
				sm.Disable()
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
		// Use a plain submenu (no checkbox) for the parent. Some hosts
		// treat a checkbox-with-children as a selectable leaf and dismiss
		// the menu instead of expanding it.
		mullvadMenu := menu.exitNodes.AddSubMenuItem("Mullvad VPN", "")

		for _, country := range mullvadExitNodes.sortedCountries() {
			title := countryFlag(country.code) + " " + country.name

			if len(country.cities) == 1 || hideMullvadCities {
				countryMenu := mullvadMenu.AddSubMenuItemCheckbox(title, "", country.hasPeer(sel))
				menu.mullvadCountryItems[country.code] = countryMenu
				setExitNodeOnClick(countryMenu, country.best.ID)
				continue
			}

			// Multi-city country: plain submenu parent so the host expands
			// it on click. Cities remain checkboxes.
			countryMenu := mullvadMenu.AddSubMenuItem(title, "")
			time.Sleep(newMenuDelay)
			bm := countryMenu.AddSubMenuItemCheckbox("Best Available", "", false)
			setExitNodeOnClick(bm, country.best.ID)
			countryMenu.AddSeparator()

			for _, city := range country.sortedCities() {
				cityMenu := countryMenu.AddSubMenuItemCheckbox(city.name, "", city.hasPeer(sel))
				menu.mullvadCityItems[country.code+"/"+city.best.Location.CityCode] = cityMenu
				setExitNodeOnClick(cityMenu, city.best.ID)
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

// hasPeer reports whether any city in mc contains a peer with the given ID.
func (mc *mvCountry) hasPeer(id tailcfg.StableNodeID) bool {
	for _, city := range mc.cities {
		if city.hasPeer(id) {
			return true
		}
	}
	return false
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

// hasPeer reports whether mc contains a peer with the given ID.
func (mc *mvCity) hasPeer(id tailcfg.StableNodeID) bool {
	for _, ps := range mc.peers {
		if ps.ID == id {
			return true
		}
	}
	return false
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
