package eventbus

import (
	"embed"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"tailscale.com/tsweb"
)

type httpDebugger struct {
	*Debugger
}

func registerHTTPDebugger(d *Debugger, td *tsweb.DebugHandler) {
	dh := httpDebugger{d}
	td.Handle("bus", "Event bus", dh)
	td.HandleSilent("bus/monitor", http.HandlerFunc(dh.serveMonitor))
	td.HandleSilent("bus/style.css", serveStatic("style.css"))
	td.HandleSilent("bus/htmx.min.js", serveStatic("htmx.min.js.gz"))
	td.HandleSilent("bus/htmx-websocket.min.js", serveStatic("htmx-websocket.min.js.gz"))
}

//go:embed assets/*.html
var templatesSrc embed.FS

var templates = sync.OnceValue(func() *template.Template {
	d, err := fs.Sub(templatesSrc, "assets")
	if err != nil {
		panic(fmt.Errorf("getting eventbus debughttp templates subdir: %w", err))
	}
	return template.Must(template.ParseFS(d, "*"))
})

//go:embed assets/*.css assets/*.min.js.gz
var static embed.FS

func serveStatic(name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(name, ".css"):
			w.Header().Set("Content-Type", "text/css")
		case strings.HasSuffix(name, ".min.js.gz"):
			w.Header().Set("Content-Type", "text/javascript")
			w.Header().Set("Content-Encoding", "gzip")
		case strings.HasSuffix(name, ".js"):
			w.Header().Set("Content-Type", "text/javascript")
		default:
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		f, err := static.Open(filepath.Join("assets", name))
		if err != nil {
			http.Error(w, fmt.Sprintf("opening asset: %v", err), http.StatusInternalServerError)
			return
		}
		defer f.Close()
		if _, err := io.Copy(w, f); err != nil {
			http.Error(w, fmt.Sprintf("serving asset: %v", err), http.StatusInternalServerError)
			return
		}
	})
}

func render(w http.ResponseWriter, name string, data any) error {
	err := templates().ExecuteTemplate(w, name+".html", data)
	if err != nil {
		err := fmt.Errorf("rendering template: %v", err)
		log.Print(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return err
	}
	return nil
}

func (h httpDebugger) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	type clientInfo struct {
		*Client
		Publish   []reflect.Type
		Subscribe []reflect.Type
	}
	type typeInfo struct {
		reflect.Type
		Publish   []*Client
		Subscribe []*Client
	}
	type info struct {
		*Debugger
		Clients map[string]*clientInfo
		Types   map[string]*typeInfo
	}

	data := info{
		Debugger: h.Debugger,
		Clients:  map[string]*clientInfo{},
		Types:    map[string]*typeInfo{},
	}

	getTypeInfo := func(t reflect.Type) *typeInfo {
		if data.Types[t.Name()] == nil {
			data.Types[t.Name()] = &typeInfo{
				Type: t,
			}
		}
		return data.Types[t.Name()]
	}

	for _, c := range h.Clients() {
		ci := &clientInfo{
			Client:    c,
			Publish:   h.PublishTypes(c),
			Subscribe: h.SubscribeTypes(c),
		}
		data.Clients[c.Name()] = ci

		for _, t := range ci.Publish {
			ti := getTypeInfo(t)
			ti.Publish = append(ti.Publish, c)
		}
		for _, t := range ci.Subscribe {
			ti := getTypeInfo(t)
			ti.Subscribe = append(ti.Subscribe, c)
		}
	}

	render(w, "main", data)
}

func (h httpDebugger) serveMonitor(w http.ResponseWriter, r *http.Request) {
	if websocket.IsWebSocketUpgrade(r) {
		h.serveMonitorStream(w, r)
		return
	}

	render(w, "monitor", nil)
}

func (h httpDebugger) serveMonitorStream(w http.ResponseWriter, r *http.Request) {
	u := websocket.Upgrader{}
	conn, err := u.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	go func() {
		for {
			if _, _, err := conn.NextReader(); err != nil {
				conn.Close()
				break
			}
		}
	}()

	mon := h.WatchBus()
	defer mon.Close()

	i := 0
	for {
		select {
		case <-r.Context().Done():
			return
		case <-mon.Done():
			return
		case event := <-mon.Events():
			log.Println(event)
			if err := conn.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
				return
			}
			msg, err := conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			data := map[string]any{
				"Count": i,
				"Type":  reflect.TypeOf(event.Event),
				"Event": event,
			}
			i++
			if err := templates().ExecuteTemplate(msg, "event.html", data); err != nil {
				log.Println(err)
				return
			}
			if err := msg.Close(); err != nil {
				return
			}
		}
	}
}
