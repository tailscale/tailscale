// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package rproxy provides a name resolver for containers working behind a docker-proxy
//
// It targets Docker Engine Api v1.24
package rproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
)

const (
	// docker Engine API addresses
	sockAddr = "/var/run/docker.sock"
	endpoint = "/containers/json"

	// argv flags for "docker-proxy" processes
	containerPort = "-container-port"
	hostPort      = "-host-port"
	proto         = "-proto"
)

// Port A struct that corresponds to an array element for "Ports" field in docker API
type Port struct {
	PrivatePort int
	PublicPort  int
	Type        string // Type can be either "tcp" or "udp"
}

// ParseDockerPort returns rproxy.Port struct from "docker-proxy" argv slice
//
// argv is expected to be in form /usr/libexec/docker/docker-proxy -proto tcp -host-ip 0.0.0.0 -host-port 3308 -container-ip 172.18.0.2 -container-port 3306
// still works if flags are arrenged differently
func ParseDockerPort(argv []string) (*Port, error) {

	l := len(argv)

	// returns if argv is empty slice or nil slice
	if len(argv) == 0 {
		return nil, fmt.Errorf("argv slice is nil or empty")
	}

	p := Port{}
	// parse flags, a sub-slice here avoids buffer overflow
	for i, e := range argv[:l-1] {
		switch e {
		case containerPort:

			v, err := strconv.Atoi(argv[i+1])
			if err != nil {
				return nil, fmt.Errorf("non integer -container-port flag value")
			}

			p.PrivatePort = v

		case hostPort:

			v, err := strconv.Atoi(argv[i+1])
			if err != nil {
				return nil, fmt.Errorf("non integer -host-port flag value")
			}
			p.PublicPort = v

		case proto:
			p.Type = argv[i+1]
		}
	}

	return &p, nil
}

// Resolver A struct that stores list of running docker containers
type Resolver struct {
	containers []container
}

func (r *Resolver) init() error {
	c, err := getDockerContainers()
	r.containers = c
	return err
}

// Resolve returns containers name, if such a container exist with given ports
//
// A container can have multiple names, if so, first one is returned
func (r *Resolver) Resolve(p Port) (name string, err error) {

	if r.containers == nil {
		if err := r.init(); err != nil {
			return name, fmt.Errorf("docker-proxy resolver cannot be initialized %v", err)
		}
	}

	for _, c := range r.containers {
		// compare to container ports
		for _, cp := range c.Ports {
			if p.PrivatePort == cp.PrivatePort && p.PublicPort == cp.PublicPort && p.Type == cp.Type {
				for _, n := range c.Names {
					return n, nil
				}
			}
		}
	}

	return name, fmt.Errorf("given Port cannot be found in docker API")
}

// json response to containers call
type container struct {
	Names []string
	Ports []Port
}

// calls docker api via unix sockets
// GET containers/json
// see: https://docs.docker.com/engine/api/v1.24/
func getDockerContainers() ([]container, error) {

	httpc := http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", sockAddr)
			},
		},
	}

	r, err := httpc.Get("http://unix" + endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch Docker API via %s : %v", endpoint, err)
	}
	var c []container

	// Try to decode the request body into the struct.
	err = json.NewDecoder(r.Body).Decode(&c)
	if err != nil {
		return nil, fmt.Errorf("failed to decode request body to struct:  %v ", err)
	}

	return c, err
}
