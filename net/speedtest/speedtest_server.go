// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package speedtest

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// Serve starts up the server on a given host and port pair. It starts to listen for
// connections and handles each one in a goroutine. Because it runs in an infinite loop,
// this function only returns if any of the speedtests return with errors, or if the
// listener is closed.
func Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		if err != nil {
			return err
		}
		err = handleConnection(conn)
		if err != nil {
			return err
		}
	}
}

// handleConnection handles the initial exchange between the server and the client.
// It reads the testconfig message into a config struct. If any errors occur with
// the testconfig (specifically, if there is a version mismatch), it will return those
// errors to the client with a configResponse. After the exchange, it will start
// the speed test.
func handleConnection(conn net.Conn) error {
	defer conn.Close()
	var conf config

	decoder := json.NewDecoder(conn)
	err := decoder.Decode(&conf)
	encoder := json.NewEncoder(conn)

	// Both return and encode errors that occurred before the test started.
	if err != nil {
		encoder.Encode(configResponse{Error: err.Error()})
		return err
	}

	// The server should always be doing the opposite of what the client is doing.
	conf.Direction.Reverse()

	if conf.Version != version {
		err = fmt.Errorf("version mismatch! Server is version %d, client is version %d", version, conf.Version)
		encoder.Encode(configResponse{Error: err.Error()})
		return err
	}

	// Start the test
	encoder.Encode(configResponse{})
	_, err = doTest(conn, conf)
	return err
}

// TODO include code to detect whether the code is direct vs DERP

// doTest contains the code to run both the upload and download speedtest.
// the direction value in the config parameter determines which test to run.
func doTest(conn net.Conn, conf config) ([]Result, error) {
	bufferData := make([]byte, blockSize)

	intervalBytes := 0
	totalBytes := 0

	var currentTime time.Time
	var results []Result

	if conf.Direction == Download {
		conn.SetReadDeadline(time.Now().Add(conf.TestDuration).Add(5 * time.Second))
	} else {
		_, err := rand.Read(bufferData)
		if err != nil {
			return nil, err
		}

	}

	startTime := time.Now()
	lastCalculated := startTime

SpeedTestLoop:
	for {
		var n int
		var err error

		if conf.Direction == Download {
			n, err = io.ReadFull(conn, bufferData)
			switch err {
			case io.EOF, io.ErrUnexpectedEOF:
				break SpeedTestLoop
			case nil:
				// successful read
			default:
				return nil, fmt.Errorf("unexpected error has occurred: %w", err)
			}
		} else {
			n, err = conn.Write(bufferData)
			if err != nil {
				// If the write failed, there is most likely something wrong with the connection.
				return nil, fmt.Errorf("upload failed: %w", err)
			}
		}
		intervalBytes += n

		currentTime = time.Now()
		// checks if the current time is more or equal to the lastCalculated time plus the increment
		if currentTime.Sub(lastCalculated) >= increment {
			results = append(results, Result{Bytes: intervalBytes, IntervalStart: lastCalculated, IntervalEnd: currentTime, Total: false})
			lastCalculated = currentTime
			totalBytes += intervalBytes
			intervalBytes = 0
		}

		if conf.Direction == Upload && currentTime.Sub(startTime) > conf.TestDuration {
			break SpeedTestLoop
		}
	}

	// get last segment
	if currentTime.Sub(lastCalculated) > minInterval {
		results = append(results, Result{Bytes: intervalBytes, IntervalStart: lastCalculated, IntervalEnd: currentTime, Total: false})
	}

	// get total
	totalBytes += intervalBytes
	if currentTime.Sub(startTime) > minInterval {
		results = append(results, Result{Bytes: totalBytes, IntervalStart: startTime, IntervalEnd: currentTime, Total: true})
	}

	return results, nil
}
