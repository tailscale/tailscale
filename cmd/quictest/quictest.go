package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/qlog"
)

func main() {
	count := flag.Int("count", 1, "times to fetch the URL(s)")
	delay := flag.Duration("duration", time.Second, "delay between --count runs")
	quiet := flag.Bool("q", false, "don't print the data")
	keyLogFile := flag.String("keylog", "", "key log file")
	insecure := flag.Bool("insecure", false, "skip certificate verification")
	flag.Parse()
	urls := flag.Args()

	var keyLog io.Writer
	if len(*keyLogFile) > 0 {
		f, err := os.Create(*keyLogFile)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		keyLog = f
	}

	pool, err := x509.SystemCertPool()
	if err != nil {
		log.Fatal(err)
	}

	roundTripper := &http3.RoundTripper{
		TLSClientConfig: &tls.Config{
			RootCAs:            pool,
			InsecureSkipVerify: *insecure,
			KeyLogWriter:       keyLog,
		},
		QUICConfig: &quic.Config{
			Tracer: qlog.DefaultConnectionTracer,
		},
	}
	defer roundTripper.Close()
	hclient := &http.Client{
		Transport: roundTripper,
	}

	for range *count {

		var wg sync.WaitGroup
		wg.Add(len(urls))
		for _, addr := range urls {
			log.Printf("GET %s", addr)
			go func(addr string) {
				rsp, err := hclient.Get(addr)
				if err != nil {
					log.Fatal(err)
				}
				log.Printf("Got response for %s: %#v", addr, rsp)

				body := &bytes.Buffer{}
				_, err = io.Copy(body, rsp.Body)
				if err != nil {
					log.Fatal(err)
				}
				if *quiet {
					log.Printf("Response Body: %d bytes", body.Len())
				} else {
					log.Printf("Response Body (%d bytes):\n%s", body.Len(), body.Bytes())
				}
				wg.Done()
			}(addr)
		}
		wg.Wait()

		time.Sleep(*delay)
	}

}
