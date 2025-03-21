// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"flag"
	"fmt"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
)

var advertiseArgs struct {
	services string // comma-separated list of services to advertise
}

// TODO(naman): This flag may move to set.go or serve_v2.go after the WIPCode
// envknob is not needed.
func advertiseCmd() *ffcli.Command {
	if !envknob.UseWIPCode() {
		return nil
	}
	return &ffcli.Command{
		Name:       "advertise",
		ShortUsage: "tailscale advertise --services=<services>",
		ShortHelp:  "Advertise this node as a destination for a service",
		Exec:       runAdvertise,
		FlagSet: (func() *flag.FlagSet {
			fs := newFlagSet("advertise")
			fs.StringVar(&advertiseArgs.services, "services", "", "comma-separated services to advertise; each must start with \"svc:\" (e.g. \"svc:idp,svc:nas,svc:database\")")
			return fs
		})(),
	}
}

func runAdvertise(ctx context.Context, args []string) error {
	if len(args) > 0 {
		return flag.ErrHelp
	}

	services, err := parseServiceNames(advertiseArgs.services)
	if err != nil {
		return err
	}
	if len(services) > 0 {
		fmt.Println("Advertising this node as new destination for services:", services)
		fmt.Println("This node will accept connection for services once the services are configured locally and approved on the admin console.")
		sc, err := localClient.GetServeConfig(ctx)
		if err != nil {
			return fmt.Errorf("failed to get serve config: %w", err)
		}
		notServedServices := make([]string, 0)
		for _, svc := range services {
			if _, ok := sc.Services[tailcfg.ServiceName(svc)]; !ok {
				notServedServices = append(notServedServices, svc)
			}
		}
		if len(notServedServices) > 0 {
			fmt.Println("The following services are not configured to be served yet: ", strings.Join(notServedServices, ", "))
			fmt.Println("To configure services, run tailscale serve --service=\"<svc:dns-label>\" for each service.")
			fmt.Printf("eg. tailscale serve --service=%q 3000\n", notServedServices[0])
		}
	}

	_, err = localClient.EditPrefs(ctx, &ipn.MaskedPrefs{
		AdvertiseServicesSet: true,
		Prefs: ipn.Prefs{
			AdvertiseServices: services,
		},
	})
	return err
}

// parseServiceNames takes a comma-separated list of service names
// (eg. "svc:hello,svc:webserver,svc:catphotos"), splits them into
// a list and validates each service name. If valid, it returns
// the service names in a slice of strings.
func parseServiceNames(servicesArg string) ([]string, error) {
	var services []string
	if servicesArg != "" {
		services = strings.Split(servicesArg, ",")
		for _, svc := range services {
			err := tailcfg.ServiceName(svc).Validate()
			if err != nil {
				return nil, fmt.Errorf("service %q: %s", svc, err)
			}
		}
	}
	return services, nil
}
