package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"runtime"
	"strings"
	"time"
)

var listen = flag.String("listen", ":8070", "listen")

func main() {
	flag.Parse()
	log.Printf("%v; listening on %v ...", runtime.Version(), *listen)
	go client()
	log.Fatal(http.ListenAndServe(*listen, http.HandlerFunc(serve)))
}

func client() {
	time.Sleep(200 * time.Millisecond)

	tr := &http.Transport{
		DisableKeepAlives: true,
	}
	connc := make(chan net.Conn, 1)
	ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
		GotConn: func(ci httptrace.GotConnInfo) {
			log.Printf("gotconn: %+v", ci)
			connc <- ci.Conn
		},
	})
	req, _ := http.NewRequestWithContext(ctx, "POST", "http://localhost:8070", nil)
	req.Header.Set("Connection", "upgrade")
	req.Header.Set("Upgrade", "tailscale")
	_, err := tr.RoundTrip(req)
	if err != nil {
		log.Printf("Failed: %v", err)
		return
	}
	//log.Printf("client got: %+v", res)
	//log.Printf("body type is %T", res.Body)

	conn := <-connc
	log.Printf("Conn was %T", conn)
	go func() {
		for {
			time.Sleep(time.Second)
			fmt.Fprintf(conn, "it is %v\n", time.Now())
		}
	}()
	_, err = io.Copy(os.Stdout, conn) // res.Body)
	log.Printf("Copy from conn: %v", err)
}

func serve(w http.ResponseWriter, r *http.Request) {
	log.Printf("server got: %+v", r)
	proto := r.Header.Get("Upgrade")
	if proto != "tailscale" {
		http.Error(w, "want tailscale", 400)
		return
	}

	conn, brw, err := w.(http.Hijacker).Hijack()
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	io.WriteString(conn, "HTTP/1.0 101 Switch Protocols\r\nContent-Length: 1234\r\nConnection: upgrade\r\nUpgrade: tailscale\r\n\r\n")
	/*w.Header().Set("Upgrade", "tailscale")
	w.Header().Set("Content-Length", "1") // bug workaround
	w.WriteHeader(101)
	w.(http.Flusher).Flush()
	*/

	defer log.Printf("ending serve")

	io.WriteString(conn, "hi.\n")

	bs := bufio.NewScanner(brw)
	for bs.Scan() {
		fmt.Fprintln(conn, strings.TrimSpace(bs.Text()))
	}
	log.Printf("Scan: %v", bs.Err())
}
