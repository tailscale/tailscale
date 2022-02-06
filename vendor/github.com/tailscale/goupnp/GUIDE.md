# Guide

This is a quick guide with example code for common use cases that might be
helpful for people wanting a quick guide to common ways that people would
want to use this library.

## Internet Gateways

`goupnp/dcps/internetgateway1` and `goupnp/dcps/internetgateway2` implement
different version standards that allow clients to interact with devices like
home consumer routers, but you can probably get by with just
`internetgateway2`. Some very common use cases to talk to such devices are:

- Requesting the external Internet-facing IP address.
- Requesting a port be forwarded from the external (Internet-facing) interface
  to a port on the LAN.

Different routers implement different standards, so you may have to request
multiple clients to find the one that your router needs. The most useful ones
for the purpose above can be requested with the following functions:

- `internetgateway2.NewWANIPConnection1Clients()`
- `internetgateway2.NewWANIPConnection2Clients()`
- `internetgateway2.NewWANPPPConnection1Clients()`

Fortunately, each of the clients returned by these functions provide the same
method signatures for the purposes listed above. So you could request multiple
clients, and whichever one you find, and return it from a function in a variable
of the common interface, e.g:

```go
type RouterClient interface {
	AddPortMapping(
		NewRemoteHost string,
		NewExternalPort uint16,
		NewProtocol string,
		NewInternalPort uint16,
		NewInternalClient string,
		NewEnabled bool,
		NewPortMappingDescription string,
		NewLeaseDuration uint32,
	) (err error)

	GetExternalIPAddress() (
		NewExternalIPAddress string,
		err error,
	)
}

func PickRouterClient(ctx context.Context) (RouterClient, error) {
	tasks, _ := errgroup.WithContext(ctx)
	// Request each type of client in parallel, and return what is found.
	var ip1Clients []*internetgateway2.WANIPConnection1
	tasks.Go(func() error {
		var err error
		ip1Clients, _, err = internetgateway2.NewWANIPConnection1Clients()
		return err
	})
	var ip2Clients []*internetgateway2.WANIPConnection2
	tasks.Go(func() error {
		var err error
		ip2Clients, _, err = internetgateway2.NewWANIPConnection2Clients()
		return err
	})
	var ppp1Clients []*internetgateway2.WANPPPConnection1
	tasks.Go(func() error {
		var err error
		ppp1Clients, _, err = internetgateway2.NewWANPPPConnection1Clients()
		return err
	})

	if err := tasks.Wait(); err != nil {
		return nil, err
	}

	// Trivial handling for where we find exactly one device to talk to, you
	// might want to provide more flexible handling than this if multiple
	// devices are found.
	switch {
	case len(ip2Clients) == 1:
		return ip2Clients[0], nil
	case len(ip1Clients) == 1:
		return ip1Clients[0], nil
	case len(ppp1Clients) == 1:
		return ppp1Clients[0], nil
	default:
		return nil, errors.New("multiple or no services found")
	}
}
```

You could then use this function to create a client, and both request the
external IP address and forward it to a port on your local network, e.g:

```go
func GetIPAndForwardPort(ctx context.Context) error {
	client, err := PickRouterClient(ctx)
	if err != nil {
		return err
	}

	externalIP, err := client.GetExternalIPAddress()
	if err != nil {
		return err
	}
	fmt.Println("Our external IP address is: ", externalIP)

	return client.AddPortMapping(
		"",
		// External port number to expose to Internet:
		1234,
		// Forward TCP (this could be "UDP" if we wanted that instead).
		"TCP",
		// Internal port number on the LAN to forward to.
		// Some routers might not support this being different to the external
		// port number.
		1234,
		// Internal address on the LAN we want to forward to.
		"192.168.1.6",
		// Enabled:
		true,
		// Informational description for the client requesting the port forwarding.
		"MyProgramName",
		// How long should the port forward last for in seconds.
		// If you want to keep it open for longer and potentially across router
		// resets, you might want to periodically request before this elapses.
		3600,
	)
}
```

The code above is of course just a relatively trivial example that you can
tailor to your own use case.
