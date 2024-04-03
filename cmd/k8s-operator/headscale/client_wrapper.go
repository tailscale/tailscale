package headscale

import (
	"context"
	"os"

	headscale "github.com/juanfont/headscale/gen/go/headscale/v1"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"tailscale.com/client/tailscale"
)

type HeadscaleClientWrapper struct {
	client headscale.HeadscaleServiceClient
	// NOTE: in headscale, user and network
	// are the same thing
	user string
}

// type and methods copied from:
// https://github.com/juanfont/headscale/blob/main/cmd/headscale/cli/utils.go
type tokenAuth struct {
	token string
}

// Return value is mapped to request headers.
func (t tokenAuth) GetRequestMetadata(
	ctx context.Context,
	in ...string,
) (map[string]string, error) {
	return map[string]string{
		"authorization": "Bearer " + t.token,
	}, nil
}

func (tokenAuth) RequireTransportSecurity() bool {
	return true
}

func NewHeadscaleClientWrapper(ctx context.Context, zlog *zap.SugaredLogger) *HeadscaleClientWrapper {
	startlog := zlog.Named("startup")

	apiAddress, set := os.LookupEnv("HEADSCALE_ADDRESS")
	if !set {
		startlog.Fatalf("HEADSCALE_ADDRESS must be set")
	}
	user, set := os.LookupEnv("HEADSCALE_USER")
	if !set {
		startlog.Fatalf("HEADSCALE_USER must be set")
	}
	apiKey, set := os.LookupEnv("HEADSCALE_API_KEY")
	if !set {
		startlog.Fatalf("HEADSCALE_API_KEY must be set")
	}

	grpcOptions := []grpc.DialOption{
		grpc.WithBlock(),
		grpc.WithPerRPCCredentials(tokenAuth{token: apiKey}),
		grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(nil, "")),
	}

	// TODO: is the context correct here?
	conn, err := grpc.DialContext(ctx, apiAddress, grpcOptions...)
	if err != nil {
		startlog.Fatalf("Error creating Headscale API client: %v", err)
	}

	return &HeadscaleClientWrapper{
		client: headscale.NewHeadscaleServiceClient(conn),
		user:   user,
	}
}

func (c *HeadscaleClientWrapper) CreateKey(ctx context.Context, caps tailscale.KeyCapabilities) (keySecret string, keyMeta *tailscale.Key, _ error) {
	// TODO: expiration 0?
	resp, err := c.client.CreatePreAuthKey(ctx, &headscale.CreatePreAuthKeyRequest{
		User:      c.user,
		Reusable:  caps.Devices.Create.Reusable,
		Ephemeral: caps.Devices.Create.Ephemeral,
		AclTags:   caps.Devices.Create.Tags,
	})
	if err != nil {
		return "", nil, err
	}

	keySecret = resp.PreAuthKey.Key
	keyMeta = &tailscale.Key{
		ID:      resp.PreAuthKey.Id,
		Created: resp.PreAuthKey.CreatedAt.AsTime(),
		Expires: resp.PreAuthKey.Expiration.AsTime(),
	}

	return keySecret, keyMeta, nil
}

func (c *HeadscaleClientWrapper) DeleteDevice(ctx context.Context, nodeStableID string) error {
	resp, err := c.client.ListNodes(ctx, &headscale.ListNodesRequest{
		User: c.user,
	})
	if err != nil {
		return err
	}

	for _, node := range resp.Nodes {
		if node.Name == nodeStableID {
			_, err := c.client.DeleteNode(ctx, &headscale.DeleteNodeRequest{
				NodeId: node.Id,
			})
			return err
		}
	}

	return nil
}
