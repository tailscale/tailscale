// The printmetric command prints out JSON of the usermetric definitions.
package main

import (
	"io/ioutil"
	"log"
	"net/http/httptest"
	"os"

	"tailscale.com/ipn/store/mem"
	"tailscale.com/tsnet"
	"tailscale.com/tstest/integration/testcontrol"
)

func main() {
	var control testcontrol.Server
	ts := httptest.NewServer(&control)
	defer ts.Close()

	td, err := ioutil.TempDir("", "testcontrol")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(td)

	tsn := &tsnet.Server{
		Dir:        td,
		Store:      new(mem.Store),
		UserLogf:   log.Printf,
		Ephemeral:  true,
		ControlURL: ts.URL,
	}
	if err := tsn.Start(); err != nil {
		log.Fatal(err)
	}
	rec := httptest.NewRecorder()
	tsn.Sys().UserMetricsRegistry().Handler(rec, httptest.NewRequest("GET", "/unused", nil))
	os.Stdout.Write(rec.Body.Bytes())
}
