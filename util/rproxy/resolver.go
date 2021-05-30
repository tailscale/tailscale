// resolver for docker-proxy
package rproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
)

// docker Engine API addresses
const (
	sockAddr = "/var/run/docker.sock"
	endpoint = "/containers/json"
)

type Port struct {
	PrivatePort int
	PublicPort  int
	Type        string // "tcp" or "udp"
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

// returns containers name, if such a conteiner exist with given ports
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
				return c.Names[0], nil
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
	var c []container

	// Try to decode the request body into the struct. If there is an error,
	// respond to the client with the error message and a 400 status code.
	err = json.NewDecoder(r.Body).Decode(&c)
	if err != nil {
		return nil, err
	}

	return c, err
}
