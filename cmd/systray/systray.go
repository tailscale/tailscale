// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build cgo || !darwin

// The systray command is a minimal Tailscale systray application for Linux.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"fyne.io/systray"
	"github.com/atotto/clipboard"
	dbus "github.com/godbus/dbus/v5"
	"github.com/toqueteos/webbrowser"
	"tailscale.com/client/tailscale"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
)

var (
	localClient tailscale.LocalClient
	chState     chan ipn.State // tailscale state changes

	appIcon *os.File
)

func main() {
	systray.Run(onReady, onExit)
}

// Menu represents the systray menu, its items, and the current Tailscale state.
type Menu struct {
	mu     sync.Mutex // protects the entire Menu
	status *ipnstate.Status

	connect    *systray.MenuItem
	disconnect *systray.MenuItem

	self *systray.MenuItem
	more *systray.MenuItem
	quit *systray.MenuItem

	eventCancel func() // cancel eventLoop
}

func onReady() {
	log.Printf("starting")
	ctx := context.Background()

	setAppIcon(disconnected)

	// dbus wants a file path for notification icons, so copy to a temp file.
	appIcon, _ = os.CreateTemp("", "tailscale-systray.png")
	io.Copy(appIcon, connected.render())

	chState = make(chan ipn.State, 1)

	status, err := localClient.Status(ctx)
	if err != nil {
		log.Print(err)
	}

	menu := new(Menu)
	menu.rebuild(status)

	go watchIPNBus(ctx)
}

// rebuild the systray menu based on the current Tailscale state.
//
// We currently rebuild the entire menu because it is not easy to update the existing menu.
// You cannot iterate over the items in a menu, nor can you remove some items like separators.
// So for now we rebuild the whole thing, and can optimize this later if needed.
func (menu *Menu) rebuild(status *ipnstate.Status) {
	menu.mu.Lock()
	defer menu.mu.Unlock()

	if menu.eventCancel != nil {
		menu.eventCancel()
	}
	menu.status = status
	systray.ResetMenu()

	menu.connect = systray.AddMenuItem("Connect", "")
	menu.disconnect = systray.AddMenuItem("Disconnect", "")
	menu.disconnect.Hide()
	systray.AddSeparator()

	if status != nil && status.Self != nil {
		title := fmt.Sprintf("This Device: %s (%s)", status.Self.HostName, status.Self.TailscaleIPs[0])
		menu.self = systray.AddMenuItem(title, "")
	}
	systray.AddSeparator()

	menu.more = systray.AddMenuItem("More settings", "")
	menu.more.Enable()

	menu.quit = systray.AddMenuItem("Quit", "Quit the app")
	menu.quit.Enable()

	ctx := context.Background()
	ctx, menu.eventCancel = context.WithCancel(ctx)
	go menu.eventLoop(ctx)
}

// eventLoop is the main event loop for handling click events on menu items
// and responding to Tailscale state changes.
// This method does not return until ctx.Done is closed.
func (menu *Menu) eventLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case state := <-chState:
			switch state {
			case ipn.Running:
				setAppIcon(loading)
				status, err := localClient.Status(ctx)
				if err != nil {
					log.Printf("error getting tailscale status: %v", err)
				}
				menu.rebuild(status)
				setAppIcon(connected)
				menu.connect.SetTitle("Connected")
				menu.connect.Disable()
				menu.disconnect.Show()
				menu.disconnect.Enable()
			case ipn.NoState, ipn.Stopped:
				menu.connect.SetTitle("Connect")
				menu.connect.Enable()
				menu.disconnect.Hide()
				setAppIcon(disconnected)
			case ipn.Starting:
				setAppIcon(loading)
			}
		case <-menu.connect.ClickedCh:
			_, err := localClient.EditPrefs(ctx, &ipn.MaskedPrefs{
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
			_, err := localClient.EditPrefs(ctx, &ipn.MaskedPrefs{
				Prefs: ipn.Prefs{
					WantRunning: false,
				},
				WantRunningSet: true,
			})
			if err != nil {
				log.Printf("disconnecting: %v", err)
				continue
			}

		case <-menu.self.ClickedCh:
			copyTailscaleIP(menu.status.Self)

		case <-menu.more.ClickedCh:
			webbrowser.Open("http://100.100.100.100/")

		case <-menu.quit.ClickedCh:
			systray.Quit()
		}
	}
}

// watchIPNBus subscribes to the tailscale event bus and sends state updates to chState.
// This method does not return.
func watchIPNBus(ctx context.Context) {
	for {
		if err := watchIPNBusInner(ctx); err != nil {
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

func watchIPNBusInner(ctx context.Context) error {
	watcher, err := localClient.WatchIPNBus(ctx, ipn.NotifyInitialState|ipn.NotifyNoPrivateKeys)
	if err != nil {
		return fmt.Errorf("watching ipn bus: %w", err)
	}
	defer watcher.Close()
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			n, err := watcher.Next()
			if err != nil {
				return fmt.Errorf("ipnbus error: %w", err)
			}
			if n.State != nil {
				chState <- *n.State
				log.Printf("new state: %v", n.State)
			}
		}
	}
}

// copyTailscaleIP copies the first Tailscale IP of the given device to the clipboard
// and sends a notification with the copied value.
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

// sendNotification sends a desktop notification with the given title and content.
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

func onExit() {
	log.Printf("exiting")
	os.Remove(appIcon.Name())
}
