package main

import (
	"context"
	"embed"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"fyne.io/systray"
	"github.com/atotto/clipboard"
	dbus "github.com/godbus/dbus/v5"
	"tailscale.com/client/tailscale"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/util/set"
)

var (
	localClient tailscale.LocalClient
	chState     chan ipn.State
	menu        Menu

	mu     sync.Mutex // mu protects status
	status *ipnstate.Status

	appIcon     *os.File
	loadingDone chan struct{}
)

//go:embed icons/*
var iconFS embed.FS

func main() {
	systray.Run(onReady, onExit)
}

type Menu struct {
	connect    *systray.MenuItem
	disconnect *systray.MenuItem

	profile     *systray.MenuItem
	profileSub  []*systray.MenuItem
	profileDone chan struct{}

	self        *systray.MenuItem
	devices     *systray.MenuItem
	devicesSub  []*systray.MenuItem
	devicesDone chan struct{}

	exitNodes        *systray.MenuItem
	noExitNode       *systray.MenuItem
	tailnetExitNodes []*systray.MenuItem
	mullvadExitNodes []*systray.MenuItem
	runExitNode      *systray.MenuItem
	currentExitNode  *systray.MenuItem

	quit *systray.MenuItem
}

func onReady() {
	log.Printf("starting")
	ctx := context.Background()

	disconnected, _ := fs.ReadFile(iconFS, "icons/disconnected.png")
	systray.SetIcon(disconnected)

	appIcon, _ = os.CreateTemp("", "tailscale-systray.png")
	connected, _ := iconFS.Open("icons/connected.png")
	io.Copy(appIcon, connected)
	connected.Close()

	var err error
	mu.Lock()
	status, err = localClient.Status(ctx)
	mu.Unlock()
	if err != nil {
		log.Print(err)
	}

	chState = make(chan ipn.State)

	menu.connect = systray.AddMenuItem("Connect", "")
	menu.disconnect = systray.AddMenuItem("Disconnect", "")
	menu.disconnect.Hide()
	systray.AddSeparator()
	menu.profile = systray.AddMenuItem("", "")
	systray.AddSeparator()

	if status != nil && status.Self != nil {
		title := fmt.Sprintf("This Device: %s (%s)", status.Self.HostName, status.Self.TailscaleIPs[0])
		menu.self = systray.AddMenuItem(title, "")
	}
	menu.devices = systray.AddMenuItem("Network Devices", "")
	systray.AddSeparator()

	menu.exitNodes = systray.AddMenuItem("Exit Nodes", "")

	menu.quit = systray.AddMenuItem("Quit", "Quit the app")
	menu.quit.Enable()

	go watchIPNBus(ctx)

	for {
		select {
		case st := <-chState:
			switch st {
			case ipn.Running:
				go loadingIcon()
				mu.Lock()
				status, err = localClient.Status(ctx)
				mu.Unlock()
				if err != nil {
					log.Print(err)
				}
				updateProfilesMenu(ctx)
				updateDevicesMenu()
				updateExitNodeMenu()
				if loadingDone != nil {
					close(loadingDone)
				}
				icon, _ := fs.ReadFile(iconFS, "icons/connected.png")
				systray.SetIcon(icon)
				menu.connect.SetTitle("Connected")
				menu.connect.Disable()
				menu.disconnect.Show()
				menu.disconnect.Enable()
			case ipn.NoState, ipn.Stopped:
				menu.connect.SetTitle("Connect")
				menu.connect.Enable()
				menu.disconnect.Hide()
				icon, _ := fs.ReadFile(iconFS, "icons/disconnected.png")
				systray.SetIcon(icon)
			case ipn.Starting:
				go loadingIcon()
			}
		case <-menu.connect.ClickedCh:
			_, err = localClient.EditPrefs(ctx, &ipn.MaskedPrefs{
				Prefs: ipn.Prefs{
					WantRunning: true,
				},
				WantRunningSet: true,
			})
			if err != nil {
				log.Print(err)
				continue
			}

		case <-menu.disconnect.ClickedCh:
			_, err = localClient.EditPrefs(ctx, &ipn.MaskedPrefs{
				Prefs: ipn.Prefs{
					WantRunning: false,
				},
				WantRunningSet: true,
			})
			if err != nil {
				log.Print(err)
				continue
			}

		case <-menu.self.ClickedCh:
			copyTailscaleIP(status.Self)

		case <-menu.quit.ClickedCh:
			systray.Quit()
		}
	}
}

func watchIPNBus(ctx context.Context) {
	watcher, err := localClient.WatchIPNBus(ctx, ipn.NotifyWatchEngineUpdates|ipn.NotifyInitialState|
		ipn.NotifyInitialPrefs|ipn.NotifyInitialNetMap)
	if err != nil {
		log.Printf("watching ipn bus: %v", err)
	}
	defer watcher.Close()
	for {
		n, err := watcher.Next()
		if err != nil {
			log.Printf("ipnbus error: %v", err)
		}
		if n.State != nil {
			chState <- *n.State
			log.Printf("new state: %v", n.State)
		}
	}
}

func updateProfilesMenu(ctx context.Context) {
	current, all, err := localClient.ProfileStatus(ctx)
	if err != nil {
		log.Print(err)
		return
	}

	// include tailnet in profile name if any two profiles have the same name
	var includeTailnet bool
	names := make(map[string]bool)
	for _, pr := range all {
		if _, ok := names[pr.Name]; ok {
			includeTailnet = true
			break
		}
		names[pr.Name] = true
	}

	title := current.Name
	if includeTailnet {
		title = fmt.Sprintf("%s\n(%s)", current.Name, current.NetworkProfile.DomainName)
	}
	menu.profile.SetTitle(title)
	if resp, err := http.Get(current.UserProfile.ProfilePicURL); err == nil {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		menu.profile.SetIcon(b)
	}

	if menu.profileDone != nil {
		close(menu.profileDone)
	}
	for _, sm := range menu.profileSub {
		sm.Remove()
	}
	menu.profileSub = nil
	menu.profileDone = make(chan struct{})

	for _, pr := range all {
		title := pr.Name
		if includeTailnet {
			title = fmt.Sprintf("%s\n(%s)", pr.Name, pr.NetworkProfile.DomainName)
		}
		sm := menu.profile.AddSubMenuItem(title, "")
		setIcon(sm, pr.UserProfile.ProfilePicURL)
		if resp, err := http.Get(pr.UserProfile.ProfilePicURL); err == nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			sm.SetIcon(b)
		}
		menu.profileSub = append(menu.profileSub, sm)
		go func() {
			for {
				select {
				case <-menu.profileDone:
					return
				case <-sm.ClickedCh:
					localClient.SwitchProfile(ctx, pr.ID)
				}
			}
		}()
	}
}

var httpCache = map[string][]byte{}

func setIcon(menu *systray.MenuItem, urlStr string) {
	if menu == nil || urlStr == "" {
		return
	}

	b, ok := httpCache[urlStr]
	if !ok {
		if resp, err := http.Get(urlStr); err == nil {
			b, _ = io.ReadAll(resp.Body)
			httpCache[urlStr] = b
			resp.Body.Close()
		}
	}

	if len(b) > 0 {
		menu.SetIcon(b)
	}
}

func updateDevicesMenu() {
	var ownerSet set.Set[tailcfg.UserProfile]
	ownerSet.Make()

	tagOwner := tailcfg.UserProfile{
		ID:          -1,
		DisplayName: "Tagged Devices",
		LoginName:   "tagged-devices",
	}
	ownedDevices := make(map[tailcfg.UserID][]*ipnstate.PeerStatus)

	for _, peer := range status.Peer {
		if peer.ShareeNode {
			continue
		}
		if peer.Tags != nil && peer.Tags.Len() > 0 {
			ownerSet.Add(tagOwner)
			ownedDevices[tagOwner.ID] = append(ownedDevices[tagOwner.ID], peer)
			continue
		}
		if peer.UserID != status.Self.UserID {
			ownerSet.Add(status.User[peer.UserID])
		}
		ownedDevices[peer.UserID] = append(ownedDevices[peer.UserID], peer)
	}

	owners := ownerSet.Slice()
	sort.SliceStable(owners, func(i, j int) bool {
		return strings.ToLower(owners[i].DisplayName) < strings.ToLower(owners[j].DisplayName)
	})

	myDevices := tailcfg.UserProfile{
		ID:          status.Self.UserID,
		DisplayName: "My Devices",
		LoginName:   status.User[status.Self.UserID].LoginName,
	}
	owners = append([]tailcfg.UserProfile{myDevices}, owners...)

	if menu.devicesDone != nil {
		close(menu.devicesDone)
	}
	for _, sm := range menu.devicesSub {
		sm.Remove()
	}
	menu.devicesSub = nil
	menu.devicesDone = make(chan struct{})

	var i int
	for _, u := range owners {
		i++
		if i > 50 {
			// FIXME: systray crashes on even moderately large menus
			more := menu.devices.AddSubMenuItem("too many items to show", "")
			more.Disable()
			menu.devicesSub = append(menu.devicesSub, more)
			break
		}
		if i == 2 {
			menu.devices.AddSeparator()
		}
		ownerMenu := menu.devices.AddSubMenuItem(u.DisplayName, "")
		loginMenu := ownerMenu.AddSubMenuItem(u.LoginName, "")
		loginMenu.Disable()
		menu.devicesSub = append(menu.devicesSub, ownerMenu)
		menu.devicesSub = append(menu.devicesSub, loginMenu)
		ownerMenu.AddSeparator()
		for _, device := range ownedDevices[u.ID] {
			name := strings.Split(device.DNSName, ".")[0]
			if name != device.HostName {
				name += " (" + device.HostName + ")"
			}
			sm := ownerMenu.AddSubMenuItem(name, "")
			menu.devicesSub = append(menu.devicesSub, sm)
			// TODO: add click handler
			go func() {
				for {
					select {
					case <-menu.devicesDone:
						return
					case <-sm.ClickedCh:
						copyTailscaleIP(device)
					}
				}
			}()
		}
	}
}

func loadingIcon() {
	loadingDone = make(chan struct{})
	var icons [][]byte
	for i := 1; i <= 16; i++ {
		b, err := fs.ReadFile(iconFS, fmt.Sprintf("icons/connecting-%d.png", i))
		if err == nil {
			icons = append(icons, b)
		}
	}

	t := time.NewTicker(300 * time.Millisecond)
	var i int
	for {
		select {
		case <-loadingDone:
			return
		case <-t.C:
			systray.SetIcon(icons[i])
			i++
			if i >= len(icons) {
				i = 0
			}
		}
	}
}

func copyTailscaleIP(device *ipnstate.PeerStatus) {
	if device == nil || len(device.TailscaleIPs) == 0 {
		return
	}
	name := strings.Split(device.DNSName, ".")[0]
	ip := device.TailscaleIPs[0].String()
	err := clipboard.WriteAll(ip)
	if err != nil {
		log.Printf("clipboard error: %v", err)
	}

	sendNotification(fmt.Sprintf("Copied Address for %v", name), ip)
}

func sendNotification(title, content string) {
	conn, err := dbus.SessionBus()
	if err != nil {
		log.Printf("dbus: %v", err)
		return
	}
	timeout := 3 * time.Second
	obj := conn.Object("org.freedesktop.Notifications", "/org/freedesktop/Notifications")
	call := obj.Call("org.freedesktop.Notifications.Notify", 0, "Tailscale", uint32(0),
		appIcon.Name(), title, content, []string{}, map[string]dbus.Variant{}, int32(timeout.Milliseconds()))
	if call.Err != nil {
		log.Printf("dbus: %v", call.Err)
	}
}

func updateExitNodeMenu() {
	msg := menu.exitNodes.AddSubMenuItem("Nothing in this menu currently works", "")
	msg.Disable()
	menu.exitNodes.AddSeparator()

	menu.noExitNode = menu.exitNodes.AddSubMenuItemCheckbox("None", "", true)
	menu.exitNodes.AddSeparator()
	tailnetNodes := menu.exitNodes.AddSubMenuItem("Tailnet Exit Nodes", "")
	tailnetNodes.Disable()
	for _, ps := range status.Peer {
		if !ps.ExitNodeOption || ps.Location != nil {
			continue
		}
		name := strings.Split(ps.DNSName, ".")[0]
		if !ps.Online {
			name += " (offline)"
		}
		sm := menu.exitNodes.AddSubMenuItemCheckbox(name, "", false)
		menu.tailnetExitNodes = append(menu.tailnetExitNodes, sm)
		if !ps.Online {
			sm.Disable()
		}
	}
	menu.exitNodes.AddSeparator()
	locationNodes := menu.exitNodes.AddSubMenuItem("Location-based Exit Nodes", "")
	locationNodes.Disable()
	mullvadNodes := menu.exitNodes.AddSubMenuItem("Mullvad VPN", "")
	menu.exitNodes.AddSeparator()
	menu.runExitNode = menu.exitNodes.AddSubMenuItemCheckbox("Run Exit Node", "", false)

	for _, country := range mullvadExitNodes() {
		cm := mullvadNodes.AddSubMenuItem(country.name, "")
		for _, city := range country.cities {
			cm.AddSubMenuItem(city.name, "")
		}
	}
}

type country struct {
	name   string
	cities map[string]*city
}

type city struct {
	name  string
	peers []*ipnstate.PeerStatus
}

func mullvadExitNodes() (nodes map[string]*country) {
	for _, ps := range status.Peer {
		if !ps.ExitNodeOption || ps.Location == nil {
			continue
		}
		if nodes == nil {
			nodes = make(map[string]*country)
		}
		loc := ps.Location
		if _, ok := nodes[loc.CountryCode]; !ok {
			nodes[loc.CountryCode] = &country{
				name:   loc.Country,
				cities: make(map[string]*city),
			}
		}
		if _, ok := nodes[loc.CountryCode].cities[loc.CityCode]; !ok {
			nodes[loc.CountryCode].cities[loc.CityCode] = &city{
				name: loc.City,
			}
		}
		c := nodes[loc.CountryCode].cities[loc.CityCode]
		c.peers = append(c.peers, ps)
	}
	return nodes
}

func onExit() {
	log.Printf("exiting")
	os.Remove(appIcon.Name())
}
