// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/go-logr/zapr"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/daemon"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"go.uber.org/zap"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/cli"
	"helm.sh/helm/v3/pkg/release"
	"helm.sh/helm/v3/pkg/storage/driver"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
	"sigs.k8s.io/controller-runtime/pkg/client"
	klog "sigs.k8s.io/controller-runtime/pkg/log"
	kzap "sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/kind/pkg/apis/config/v1alpha4"
	"sigs.k8s.io/kind/pkg/cluster"
	"sigs.k8s.io/kind/pkg/cluster/nodeutils"
	"sigs.k8s.io/kind/pkg/cmd"

	"tailscale.com/client/tailscale/v2"
	"tailscale.com/cmd/k8s-operator/e2e/internal/build"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store/mem"
	tsoperator "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/tsnet"
	"tailscale.com/util/must"
)

const (
	pebbleTag           = "2.8.0"
	ns                  = "default"
	tmp                 = "/tmp/k8s-operator-e2e"
	kindClusterName     = "k8s-operator-e2e"
	testCAsConfigMap    = "test-cas"
	testCAsConfigMapKey = "test-cas.pem"
)

var (
	tsClient           *tailscale.Client // For API calls to control.
	tnClient           *tsnet.Server     // For testing real tailnet traffic on first tailnet.
	secondTSClient     *tailscale.Client // For API calls to the secondary tailnet (_second_tailnet).
	secondTNClient     *tsnet.Server     // For testing real tailnet traffic on second tailnet.
	restCfg            *rest.Config      // For constructing a client-go client if necessary.
	kubeClient         client.WithWatch  // For k8s API calls.
	clusterLoginServer string
	clusterIPv4Support bool // whether the test cluster supports IPv4.
	clusterIPv6Support bool // whether the test cluster supports IPv6.

	//go:embed certs/pebble.minica.crt
	pebbleMiniCACert []byte

	// Let's Encrypt staging environment root "Pretend Pear X1", used when
	// running against real tailnets.
	// Available from https://letsencrypt.org/certs/staging/letsencrypt-stg-root-x1.pem
	//go:embed certs/letsencrypt-stg-root-x1.pem
	leStagingRootX1 []byte

	// Either pebble CAs (if pebble is deployed for devcontrol) or Let's Encrypt
	// staging (when running against real tailnets).
	// pebble has a static "mini" CA that its ACME directory URL serves a cert from,
	// and also dynamically generates a different CA for issuing certs.
	testCAs = x509.NewCertPool()

	//go:embed acl.hujson
	requiredACLs []byte

	fDevcontrol = flag.Bool("devcontrol", false, "if true, connect to devcontrol at http://localhost:31544. Run devcontrol with "+`
	./tool/go run ./cmd/devcontrol \
		--generate-test-devices=k8s-operator-e2e \
		--dir=/tmp/devcontrol \
		--scenario-output-dir=/tmp/k8s-operator-e2e \
		--test-dns=http://localhost:8055`)
	fSkipCleanup = flag.Bool("skip-cleanup", false, "if true, do not delete the kind cluster (if created) or tmp dir on exit")
	fCluster     = flag.Bool("cluster", false, "if true, create or use a pre-existing kind cluster named k8s-operator-e2e; otherwise assume a usable cluster already exists in kubeconfig")
	fBuild       = flag.Bool("build", false, "if true, build and deploy the operator and container images from the current checkout; otherwise assume the operator is already running and the required images are available in the registry")
	fBaseImage   = flag.String("base-image", "", "if set, use this image as the base for all images built by --build, instead of the default base image in build_docker.sh")
	fRegistry    = flag.String("registry", "", `if set, use images from this registry instead of loading them into a kind node. Required with --build when testing against a remote cluster.`)
)

func runTests(m *testing.M) (int, error) {
	logger := kzap.NewRaw().Sugar()
	klog.SetLogger(zapr.NewLogger(logger.Desugar()))
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	switch {
	case *fCluster && *fRegistry != "":
		return 0, fmt.Errorf("--cluster side-loads images into the kind node and doesn't take --registry")
	case *fBuild && !*fCluster && *fRegistry == "":
		return 0, fmt.Errorf("--build without --cluster needs --registry to push images to; there is no kind node to side-load into")
	}

	ossDir, err := build.RepoRoot()
	if err != nil {
		return 0, err
	}

	if err = os.MkdirAll(tmp, 0755); err != nil {
		return 0, fmt.Errorf("failed to create temp dir: %w", err)
	}

	logger.Infof("temp dir: %q", tmp)
	logger.Infof("oss dir: %q", ossDir)

	var (
		kubeconfig   string
		kindProvider *cluster.Provider
	)
	if *fCluster {
		kubeconfig = filepath.Join(tmp, "kubeconfig")
		kindProvider = cluster.NewProvider(
			cluster.ProviderWithLogger(cmd.NewLogger()),
		)

		clusters, err := kindProvider.List()
		if err != nil {
			return 0, fmt.Errorf("failed to list kind clusters: %w", err)
		}

		if !slices.Contains(clusters, kindClusterName) {
			if err := kindProvider.Create(kindClusterName,
				cluster.CreateWithV1Alpha4Config(&v1alpha4.Cluster{
					Networking: v1alpha4.Networking{
						IPFamily: v1alpha4.DualStackFamily,
					},
				}),
				cluster.CreateWithWaitForReady(5*time.Minute),
				cluster.CreateWithKubeconfigPath(kubeconfig),
				cluster.CreateWithNodeImage("kindest/node:v1.35.0"),
			); err != nil {
				return 0, fmt.Errorf("failed to create kind cluster: %w", err)
			}
		}

		if !*fSkipCleanup {
			defer kindProvider.Delete(kindClusterName, kubeconfig)
			defer os.Remove(kubeconfig)
		}
	}

	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		loadingRules.ExplicitPath = kubeconfig
	}
	restCfg, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		return 0, fmt.Errorf("error loading kubeconfig: %w", err)
	}

	kubeClient, err = client.NewWithWatch(restCfg, client.Options{Scheme: tsapi.GlobalScheme})
	if err != nil {
		return 0, fmt.Errorf("error creating Kubernetes client: %w", err)
	}

	if err := detectClusterIPFamilies(ctx, logger, kubeClient); err != nil {
		return 0, fmt.Errorf("error detecting cluster IP families: %w", err)
	}

	var (
		operatorCreds       oauthCreds // Operator's OAuth client for the first tailnet.
		secondOperatorCreds oauthCreds // Operator's OAuth client for the second tailnet.

		imageCAPaths  []string // Extra CAs the image needs in its system trust store to issue certs; it is only populated for pebble.
		pebbleCAChain []byte
	)
	if *fDevcontrol {
		// Deploy pebble and get its certs.
		if err = applyPebbleResources(ctx, kubeClient); err != nil {
			return 0, fmt.Errorf("failed to apply pebble resources: %w", err)
		}

		pebblePod, err := waitForPodReady(ctx, logger, kubeClient, ns, client.MatchingLabels{"app": "pebble"})
		if err != nil {
			return 0, fmt.Errorf("pebble pod not ready: %w", err)
		}

		if err = forwardLocalPortToPod(ctx, logger, restCfg, ns, pebblePod, 15000); err != nil {
			return 0, fmt.Errorf("failed to set up port forwarding to pebble: %w", err)
		}

		if !testCAs.AppendCertsFromPEM(pebbleMiniCACert) {
			return 0, fmt.Errorf("failed to parse pebble minica cert")
		}

		for _, path := range []string{"/intermediates/0", "/roots/0"} {
			pem, err := pebbleGet(ctx, 15000, path)
			if err != nil {
				return 0, err
			}
			pebbleCAChain = append(pebbleCAChain, pem...)
		}

		if !testCAs.AppendCertsFromPEM(pebbleCAChain) {
			return 0, fmt.Errorf("failed to parse pebble CA chain certs")
		}

		certsDir := filepath.Join(tmp, "certs")
		if err = os.MkdirAll(certsDir, 0755); err != nil {
			return 0, fmt.Errorf("failed to create certs dir: %w", err)
		}

		// Only the static minica needs baking into images: it ensures pebble's
		// ACME directory endpoint is verified via the system roots. The
		// dynamically-generated issuing CA chain above deliberately isn't baked
		// in because it changes on every pebble restart and images may be built
		// before pebble exists. Clients that need to query URLs whose cert is
		// rooted in the dynamic CA chain should use the ConfigMap published to
		// [testCAsConfigMap].
		pebbleMiniCACertPath := filepath.Join(certsDir, "pebble.minica.crt")
		if err = os.WriteFile(pebbleMiniCACertPath, pebbleMiniCACert, 0644); err != nil {
			return 0, fmt.Errorf("failed to write pebble minica: %w", err)
		}

		imageCAPaths = []string{pebbleMiniCACertPath}
		if !*fSkipCleanup {
			defer os.RemoveAll(certsDir)
		}

		// Set up network connectivity between cluster and devcontrol.
		//
		// For devcontrol -> pebble (DNS mgmt for ACME challenges):
		// * Port forward from localhost port 8055 to in-cluster pebble port 8055.
		//
		// For Pods -> devcontrol (tailscale clients joining the tailnet):
		// * Create ssh-server Deployment in cluster.
		// * Create reverse ssh tunnel that goes from ssh-server port 31544 to localhost:31544.
		if err = forwardLocalPortToPod(ctx, logger, restCfg, ns, pebblePod, 8055); err != nil {
			return 0, fmt.Errorf("failed to set up port forwarding to pebble: %w", err)
		}

		privateKey, publicKey, err := readOrGenerateSSHKey(tmp)
		if err != nil {
			return 0, fmt.Errorf("failed to read or generate SSH key: %w", err)
		}

		if !*fSkipCleanup {
			defer os.Remove(privateKeyPath)
		}

		sshServiceIP, err := connectClusterToDevcontrol(ctx, logger, kubeClient, restCfg, privateKey, publicKey)
		if err != nil {
			return 0, fmt.Errorf("failed to set up cluster->devcontrol connection: %w", err)
		}

		if !*fSkipCleanup {
			defer func() {
				if err := cleanupSSHResources(context.Background(), kubeClient); err != nil {
					logger.Infof("failed to clean up ssh-server resources: %v", err)
				}
			}()
		}

		// Address cluster workloads can reach devcontrol at. Must be a private
		// IP to make sure tailscale client code recognises it shouldn't try an
		// https fallback. See [controlclient.NewNoiseClient] for details.
		clusterLoginServer = "http://" + net.JoinHostPort(sshServiceIP, "31544")

		b, err := os.ReadFile(filepath.Join(tmp, "api-key.json"))
		if err != nil {
			return 0, fmt.Errorf("failed to read api-key.json: %w", err)
		}
		var apiKeyData struct {
			APIKey string `json:"apiKey"`
		}
		if err = json.Unmarshal(b, &apiKeyData); err != nil {
			return 0, fmt.Errorf("failed to parse api-key.json: %w", err)
		}
		if apiKeyData.APIKey == "" {
			return 0, fmt.Errorf("api-key.json did not contain an API key")
		}

		// Finish setting up tsClient.
		tsClient = &tailscale.Client{
			APIKey:  apiKeyData.APIKey,
			BaseURL: must.Get(url.Parse("http://localhost:31544")),
		}

		// Set ACLs and create OAuth client.
		if err = tsClient.PolicyFile().Set(ctx, string(requiredACLs), ""); err != nil {
			return 0, fmt.Errorf("failed to set policy file: %w", err)
		}

		logger.Info("ACLs configured for first tailnet")

		key, err := tsClient.Keys().CreateOAuthClient(ctx, tailscale.CreateOAuthClientRequest{
			Scopes:      []string{"auth_keys", "devices:core", "services"},
			Tags:        []string{"tag:k8s-operator"},
			Description: "k8s-operator client for e2e tests",
		})
		if err != nil {
			return 0, fmt.Errorf("failed to create OAuth client for first tailnet: %w", err)
		}
		operatorCreds = oauthCreds{
			clientID:     key.ID,
			clientSecret: key.Key,
		}

		logger.Info("OAuth credentials set for first tailnet")

		// Create second tailnet. The bootstrap credentials returned have 'all' permissions-
		// they are used for administrative actions and to create a separately scoped
		// Oauth client for the k8s operator.
		bootstrapClient, err := createTailnet(ctx, tsClient)
		if err != nil {
			return 0, fmt.Errorf("failed to create second tailnet: %w", err)
		}

		// Set HTTPS on second tailnet.
		err = bootstrapClient.TailnetSettings().Update(ctx, tailscale.UpdateTailnetSettingsRequest{HTTPSEnabled: new(true)})
		if err != nil {
			return 0, fmt.Errorf("failed to configure https for second tailnet: %w", err)
		}
		logger.Info("HTTPS settings configured for second tailnet")

		// Set ACLs for second tailnet.
		if err = bootstrapClient.PolicyFile().Set(ctx, string(requiredACLs), ""); err != nil {
			return 0, fmt.Errorf("failed to set policy file: %w", err)
		}

		logger.Info("ACLs configured for second tailnet")

		// Create an OAuth client for the second tailnet to be used
		// by the k8s-operator.
		secondKey, err := bootstrapClient.Keys().CreateOAuthClient(ctx, tailscale.CreateOAuthClientRequest{
			Scopes:      []string{"auth_keys", "devices:core", "services"},
			Tags:        []string{"tag:k8s-operator"},
			Description: "k8s-operator client for e2e tests",
		})
		if err != nil {
			return 0, fmt.Errorf("failed to create OAuth client for second tailnet: %w", err)
		}
		secondOperatorCreds = oauthCreds{
			clientID:     secondKey.ID,
			clientSecret: secondKey.Key,
		}

		secondTSClient = tailscaleClientFromSecret("http://localhost:31544", secondOperatorCreds.clientID, secondOperatorCreds.clientSecret)
	} else {
		if !testCAs.AppendCertsFromPEM(leStagingRootX1) {
			return 0, fmt.Errorf("failed to parse Let's Encrypt staging root X1 cert")
		}
		tsClient, operatorCreds, err = prodTailnetClientFromEnv("TS_API_CLIENT_SECRET", "TS_API_CLIENT_ID", "TS_OPERATOR_CLIENT_ID")
		if err != nil {
			return 0, fmt.Errorf("failed to set up first tailnet clients: %w", err)
		}
		secondTSClient, secondOperatorCreds, err = prodTailnetClientFromEnv("SECOND_TS_API_CLIENT_SECRET", "SECOND_TS_API_CLIENT_ID", "SECOND_TS_OPERATOR_CLIENT_ID")
		if err != nil {
			return 0, fmt.Errorf("failed to set up second tailnet clients: %w", err)
		}
	}

	// Publish the trustedCAs as a ConfigMap that can be used by in-cluster
	// testing workloads.
	testCAPEM := leStagingRootX1
	if *fDevcontrol {
		testCAPEM = bytes.Join([][]byte{pebbleMiniCACert, pebbleCAChain}, []byte("\n"))
	}
	caCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: testCAsConfigMap, Namespace: ns},
		Data:       map[string]string{testCAsConfigMapKey: string(testCAPEM)},
	}
	if err := createOrUpdate(ctx, kubeClient, caCM); err != nil {
		return 0, fmt.Errorf("failed to publish test CAs ConfigMap: %w", err)
	}
	defer kubeClient.Delete(context.Background(), caCM)

	var ossTag string
	if *fBuild || *fRegistry != "" {
		var dirty bool
		ossTag, dirty, err = build.Tag(ossDir)
		if err != nil {
			return 0, err
		}
		logger.Infof("using OSS image tag: %q", ossTag)
		if !*fBuild && dirty {
			// Without --build the images must already exist in the registry,
			// but a dirty tree gets a random tag suffix that nothing has
			// pushed.
			return 0, fmt.Errorf("--registry without --build derives the image tag from the current commit, which requires a clean working tree")
		}
	}
	if *fBuild {
		// TODO(tomhjp): proper support for --build=false and layering pebble certs on top of existing images.
		// TODO(tomhjp): build tsrecorder as well.

		if *fBaseImage != "" {
			logger.Infof("using base image: %q", *fBaseImage)
		}
		opts := build.Opts{
			Dir:          ossDir,
			Registry:     *fRegistry,
			Tag:          ossTag,
			BaseImage:    *fBaseImage,
			ExtraCACerts: imageCAPaths,
			Logf:         logger.Infof,
		}
		if *fRegistry != "" {
			opts.Arch, err = detectNodeArch(ctx, kubeClient)
			if err != nil {
				return 0, fmt.Errorf("failed to detect node architecture: %w", err)
			}
			logger.Infof("building images for node architecture %q, pushing to %q", opts.Arch, *fRegistry)
			if err := build.EnsurePushed(ctx, opts); err != nil {
				return 0, err
			}
		} else {
			for imgName := range build.Targets {
				if err := build.Build(ctx, opts, imgName); err != nil {
					return 0, err
				}
				nodes, err := kindProvider.ListInternalNodes(kindClusterName)
				if err != nil {
					return 0, fmt.Errorf("failed to list kind nodes: %w", err)
				}
				// TODO(tomhjp): can be made more efficient and portable if we
				// stream built image tarballs straight to the node rather than
				// going via the daemon.
				imgRef, err := name.ParseReference(fmt.Sprintf("%s:%s", build.ImageRepo("", imgName), ossTag))
				if err != nil {
					return 0, fmt.Errorf("failed to parse image reference: %w", err)
				}
				img, err := daemon.Image(imgRef)
				if err != nil {
					return 0, fmt.Errorf("failed to get image from daemon: %w", err)
				}
				pr, pw := io.Pipe()
				go func() {
					defer pw.Close()
					if err := tarball.Write(imgRef, img, pw); err != nil {
						logger.Infof("failed to write image to pipe: %v", err)
					}
				}()
				for _, n := range nodes {
					if err := nodeutils.LoadImageArchive(n, pr); err != nil {
						return 0, fmt.Errorf("failed to load image into node %q: %w", n.String(), err)
					}
				}
			}
		}
	}

	// Generate CRDs for the helm chart.
	cmd := exec.CommandContext(ctx, "go", "run", "tailscale.com/cmd/k8s-operator/generate", "helmcrd")
	cmd.Dir = ossDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("failed to generate CRD: %v: %s", err, out)
	}

	// Load and install helm chart.
	chart, err := loader.Load(filepath.Join(ossDir, "cmd", "k8s-operator", "deploy", "chart"))
	if err != nil {
		return 0, fmt.Errorf("failed to load helm chart: %w", err)
	}
	// Image repo/tag are left empty unless we built or were given prebuilt
	// images (ossTag is set), so the chart uses the 'stable' defaults.
	var operatorRepo, proxyRepo, imageTag string
	var extraEnv []map[string]any
	if ossTag != "" {
		operatorRepo, proxyRepo, imageTag = build.ImageRepo(*fRegistry, build.ImgOperator), build.ImageRepo(*fRegistry, build.ImgTailscale), ossTag
		extraEnv = append(extraEnv, map[string]any{"name": "K8S_PROXY_IMAGE", "value": build.ImageRepo(*fRegistry, build.ImgProxy) + ":" + ossTag})
	}
	if *fDevcontrol {
		extraEnv = append(extraEnv, map[string]any{"name": "TS_DEBUG_ACME_DIRECTORY_URL", "value": "https://pebble:14000/dir"})
	} else {
		extraEnv = append(extraEnv, map[string]any{"name": "TS_DEBUG_ACME_DIRECTORY_URL", "value": "https://acme-staging-v02.api.letsencrypt.org/directory"})
	}
	oauthValues := map[string]any{
		"clientId": operatorCreds.clientID,
	}
	if operatorCreds.audience != "" {
		oauthValues["audience"] = operatorCreds.audience
	} else {
		oauthValues["clientSecret"] = operatorCreds.clientSecret
	}
	values := map[string]any{
		"loginServer": clusterLoginServer,
		"oauth":       oauthValues,
		"apiServerProxyConfig": map[string]any{
			"mode": "true",
		},
		"operatorConfig": map[string]any{
			"logging":  "debug",
			"extraEnv": extraEnv,
			"image": map[string]any{
				"repo":       operatorRepo,
				"tag":        imageTag,
				"pullPolicy": "IfNotPresent",
			},
		},
		"proxyConfig": map[string]any{
			"defaultProxyClass": "default",
			"image": map[string]any{
				"repo": proxyRepo,
				"tag":  imageTag,
			},
		},
	}

	settings := cli.New()
	settings.KubeConfig = kubeconfig
	settings.SetNamespace("tailscale")
	helmCfg := &action.Configuration{}
	if err := helmCfg.Init(settings.RESTClientGetter(), "tailscale", "", logger.Infof); err != nil {
		return 0, fmt.Errorf("failed to initialize helm action configuration: %w", err)
	}

	const relName = "tailscale-operator" // TODO(tomhjp): maybe configurable if others use a different value.
	f := upgraderOrInstaller(helmCfg, relName)
	if _, err := f(ctx, relName, chart, values); err != nil {
		return 0, fmt.Errorf("failed to install %q via helm: %w", relName, err)
	}

	if err := applyDefaultProxyClass(ctx, logger, kubeClient); err != nil {
		return 0, fmt.Errorf("failed to apply default ProxyClass: %w", err)
	}

	// Leave the nameserver image unset when nothing was built so
	// the operator falls back to the default.
	nameserverImg := &tsapi.NameserverImage{}
	if ossTag != "" {
		nameserverImg.Repo = build.ImageRepo(*fRegistry, build.ImgNameserver)
		nameserverImg.Tag = ossTag
	}
	dnsConfig, err := deployNameserver(ctx, logger, kubeClient, nameserverImg)
	if err != nil {
		return 0, fmt.Errorf("failed to deploy nameserver: %w", err)
	}
	defer kubeClient.Delete(context.Background(), dnsConfig)

	restoreClusterDNS, err := patchClusterDNS(ctx, logger, dnsConfig.Status.Nameserver.IP)
	if err != nil {
		return 0, fmt.Errorf("failed to patch cluster DNS: %w", err)
	}
	defer restoreClusterDNS()

	caps := tailscale.KeyCapabilities{}
	caps.Devices.Create.Preauthorized = true
	caps.Devices.Create.Ephemeral = true
	caps.Devices.Create.Tags = []string{"tag:k8s"}

	authKey, err := tsClient.Keys().CreateAuthKey(ctx, tailscale.CreateKeyRequest{Capabilities: caps})
	if err != nil {
		return 0, fmt.Errorf("failed to create auth key for first tailnet: %w", err)
	}
	defer tsClient.Keys().Delete(context.Background(), authKey.ID)

	secondAuthKey, err := secondTSClient.Keys().CreateAuthKey(ctx, tailscale.CreateKeyRequest{Capabilities: caps})
	if err != nil {
		return 0, fmt.Errorf("failed to create auth key for second tailnet: %w", err)
	}
	defer secondTSClient.Keys().Delete(context.Background(), secondAuthKey.ID)

	tnClient = &tsnet.Server{
		ControlURL: tsClient.BaseURL.String(),
		Hostname:   "test-proxy",
		Ephemeral:  true,
		Store:      &mem.Store{},
		AuthKey:    authKey.Key,
	}
	_, err = tnClient.Up(ctx)
	if err != nil {
		return 0, err
	}
	defer tnClient.Close()

	secondTNClient = &tsnet.Server{
		ControlURL: secondTSClient.BaseURL.String(),
		Hostname:   "test-proxy",
		Ephemeral:  true,
		Store:      &mem.Store{},
		AuthKey:    secondAuthKey.Key,
	}
	_, err = secondTNClient.Up(ctx)
	if err != nil {
		return 0, err
	}
	defer secondTNClient.Close()

	// Create the tailnet Secret in the tailscale namespace.
	secretData := map[string][]byte{
		"client_id": []byte(secondOperatorCreds.clientID),
	}
	if secondOperatorCreds.audience != "" {
		secretData["audience"] = []byte(secondOperatorCreds.audience)
	} else {
		secretData["client_secret"] = []byte(secondOperatorCreds.clientSecret)
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "second-tailnet-credentials",
			Namespace: "tailscale",
		},
		Data: secretData,
	}
	if err := createOrUpdate(ctx, kubeClient, secret); err != nil {
		return 0, fmt.Errorf("failed to create second-tailnet-credentials Secret: %w", err)
	}
	defer kubeClient.Delete(context.Background(), secret)

	// Create the Tailnet resource.
	tn := &tsapi.Tailnet{
		ObjectMeta: metav1.ObjectMeta{
			Name: "second-tailnet",
		},
		Spec: tsapi.TailnetSpec{
			LoginURL: clusterLoginServer,
			Credentials: tsapi.TailnetCredentials{
				SecretName: "second-tailnet-credentials",
			},
		},
	}
	if err := createOrUpdate(ctx, kubeClient, tn); err != nil {
		return 0, fmt.Errorf("failed to create second-tailnet Tailnet: %w", err)
	}
	defer kubeClient.Delete(context.Background(), tn)

	return m.Run(), nil
}

func clientIDFromSecret(clientSecret string) (string, error) {
	// Format is "tskey-client-<id>-<random>".
	parts := strings.Split(clientSecret, "-")
	if len(parts) != 4 {
		return "", fmt.Errorf("secret is not valid")
	}
	return parts[2], nil
}

// oauthCreds identifies an OAuth client for the operator to authenticate as.
// Exactly one of clientSecret or audience is set; audience means a workload
// identity federation client, and the operator mints ServiceAccount tokens
// for itself to exchange for API tokens.
type oauthCreds struct {
	clientID     string
	clientSecret string
	audience     string
}

// prodTailnetClientFromEnv returns an API client for the harness plus creds for
// the operator to use against one prod tailnet. If secretEnv is set, its static
// OAuth client is used for both. Otherwise, workload identity federation is
// configured, and allows the tests (clientIDEnv) to use a different token issuer
// than the operator (operatorClientIDEnv).
func prodTailnetClientFromEnv(secretEnv, clientIDEnv, operatorClientIDEnv string) (*tailscale.Client, oauthCreds, error) {
	if secret := os.Getenv(secretEnv); secret != "" {
		id, err := clientIDFromSecret(secret)
		if err != nil {
			return nil, oauthCreds{}, fmt.Errorf("failed to get client id from %s: %w", secretEnv, err)
		}
		creds := oauthCreds{
			clientID:     id,
			clientSecret: secret,
		}
		return tailscaleClientFromSecret(ipn.DefaultControlURL, id, secret), creds, nil
	}

	clientID := os.Getenv(clientIDEnv)
	operatorClientID := os.Getenv(operatorClientIDEnv)
	if clientID == "" || operatorClientID == "" {
		return nil, oauthCreds{}, fmt.Errorf("must use --devcontrol, or set %s to a static OAuth client secret, or set both %s and %s to workload identity federation OAuth client IDs", secretEnv, clientIDEnv, operatorClientIDEnv)
	}
	client := &tailscale.Client{
		BaseURL: must.Get(url.Parse(ipn.DefaultControlURL)),
		Auth: &tailscale.IdentityFederation{
			ClientID:    clientID,
			IDTokenFunc: githubIDToken(audienceForClient(clientID)),
		},
	}
	creds := oauthCreds{
		clientID: operatorClientID,
		audience: audienceForClient(operatorClientID),
	}
	return client, creds, nil
}

// audienceForClient returns the audience Tailscale generates for a workload
// identity federation OAuth client.
// See https://tailscale.com/kb/1581/workload-identity-federation.
func audienceForClient(clientID string) string {
	return "api.tailscale.com/" + clientID
}

// githubIDToken returns a function that fetches an OIDC ID token from the
// ambient GitHub Actions environment, which requires the job to have the
// id-token: write permission.
// See https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect.
func githubIDToken(audience string) func() (string, error) {
	return func() (string, error) {
		reqURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
		reqToken := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
		if reqURL == "" || reqToken == "" {
			return "", errors.New("ACTIONS_ID_TOKEN_REQUEST_URL and ACTIONS_ID_TOKEN_REQUEST_TOKEN must be set; GitHub OIDC tokens are only available in GitHub Actions jobs with the id-token: write permission")
		}
		req, err := http.NewRequest("GET", reqURL+"&audience="+url.QueryEscape(audience), nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("Authorization", "Bearer "+reqToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return "", fmt.Errorf("failed to fetch GitHub OIDC token: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			return "", fmt.Errorf("GitHub OIDC token request failed with status %d: %s", resp.StatusCode, b)
		}
		var token struct {
			Value string `json:"value"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
			return "", fmt.Errorf("failed to decode GitHub OIDC token response: %w", err)
		}
		return token.Value, nil
	}
}

func upgraderOrInstaller(cfg *action.Configuration, releaseName string) helmInstallerFunc {
	hist := action.NewHistory(cfg)
	hist.Max = 1
	helmVersions, err := hist.Run(releaseName)
	if err == driver.ErrReleaseNotFound || (len(helmVersions) > 0 && helmVersions[0].Info.Status == release.StatusUninstalled) {
		return helmInstaller(cfg, releaseName)
	} else {
		return helmUpgrader(cfg)
	}
}

func helmUpgrader(cfg *action.Configuration) helmInstallerFunc {
	upgrade := action.NewUpgrade(cfg)
	upgrade.Namespace = "tailscale"
	upgrade.Install = true
	upgrade.Wait = true
	upgrade.Timeout = 5 * time.Minute
	return upgrade.RunWithContext
}

func helmInstaller(cfg *action.Configuration, releaseName string) helmInstallerFunc {
	install := action.NewInstall(cfg)
	install.Namespace = "tailscale"
	install.CreateNamespace = true
	install.ReleaseName = releaseName
	install.Wait = true
	install.Timeout = 5 * time.Minute
	install.Replace = true
	return func(ctx context.Context, _ string, chart *chart.Chart, values map[string]any) (*release.Release, error) {
		return install.RunWithContext(ctx, chart, values)
	}
}

type helmInstallerFunc func(context.Context, string, *chart.Chart, map[string]any) (*release.Release, error)

func applyDefaultProxyClass(ctx context.Context, logger *zap.SugaredLogger, cl client.Client) error {
	var env []tsapi.Env
	if *fDevcontrol {
		env = []tsapi.Env{
			{
				Name:  "TS_DEBUG_ACME_DIRECTORY_URL",
				Value: "https://pebble:14000/dir",
			},
		}
	}
	pc := &tsapi.ProxyClass{
		TypeMeta: metav1.TypeMeta{
			APIVersion: tsapi.SchemeGroupVersion.String(),
			Kind:       tsapi.ProxyClassKind,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
		Spec: tsapi.ProxyClassSpec{
			UseLetsEncryptStagingEnvironment: !*fDevcontrol,
			StatefulSet: &tsapi.StatefulSet{
				Pod: &tsapi.Pod{
					TailscaleInitContainer: &tsapi.Container{
						ImagePullPolicy: "IfNotPresent",
					},
					TailscaleContainer: &tsapi.Container{
						ImagePullPolicy: "IfNotPresent",
						Env:             env,
					},
				},
			},
		},
	}

	owner := client.FieldOwner("k8s-test")
	if err := cl.Patch(ctx, pc, client.Apply, owner); err != nil {
		return fmt.Errorf("failed to apply default ProxyClass: %w", err)
	}

	// Wait for the ProxyClass to be marked ready.
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	for {
		if err := cl.Get(ctx, client.ObjectKeyFromObject(pc), pc); err != nil {
			return fmt.Errorf("failed to get default ProxyClass: %w", err)
		}
		if tsoperator.ProxyClassIsReady(pc) {
			break
		}
		logger.Info("waiting for default ProxyClass to be ready...")
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for default ProxyClass to be ready")
		case <-time.After(time.Second):
		}
	}

	return nil
}

func deployNameserver(ctx context.Context, logger *zap.SugaredLogger, cl client.Client, img *tsapi.NameserverImage) (*tsapi.DNSConfig, error) {
	dc := &tsapi.DNSConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "dns"},
		Spec:       tsapi.DNSConfigSpec{Nameserver: &tsapi.Nameserver{Image: img}},
	}
	if err := createOrUpdate(ctx, cl, dc); err != nil {
		return nil, fmt.Errorf("failed to create DNSConfig: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	ticker := time.NewTicker(time.Second * 2)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("timeout waiting for nameserver to be ready")
		case <-ticker.C:
			if err := cl.Get(ctx, client.ObjectKeyFromObject(dc), dc); err != nil {
				return nil, fmt.Errorf("failed to get DNSConfig: %w", err)
			}
			if tsoperator.DNSCfgIsReady(dc) && dc.Status.Nameserver != nil && dc.Status.Nameserver.IP != "" {
				logger.Infof("nameserver ready; Service IP %s", dc.Status.Nameserver.IP)
				return dc, nil
			}
			logger.Info("waiting for nameserver to be ready...")
		}
	}
}

func patchClusterDNS(ctx context.Context, logger *zap.SugaredLogger, nameserverIP string) (func(), error) {
	if cm := getDNSConfigMap(ctx, "coredns"); cm != nil && cm.Data["Corefile"] != "" {
		corefile := stripTSNetZone(cm.Data["Corefile"]) + fmt.Sprintf(`
ts.net:53 {
    errors
    cache 30
    forward . %s
}
`, nameserverIP)
		return patchDNSConfigMap(logger, cm, "Corefile", corefile)
	}
	if cm := getDNSConfigMap(ctx, "kube-dns"); cm != nil {
		stub, err := json.Marshal(map[string][]string{"ts.net": {nameserverIP}})
		if err != nil {
			return nil, fmt.Errorf("marshalling stubDomains: %w", err)
		}
		return patchDNSConfigMap(logger, cm, "stubDomains", string(stub))
	}
	return nil, fmt.Errorf("cluster DNS is not a patchable CoreDNS/kube-dns")
}

func getDNSConfigMap(ctx context.Context, name string) *corev1.ConfigMap {
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: name}}
	if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(cm), cm); err != nil {
		return nil
	}
	return cm
}

// patchDNSConfigMap updates the given Configmap and returns a closure
// for test cleanup.
func patchDNSConfigMap(logger *zap.SugaredLogger, cm *corev1.ConfigMap, key, value string) (func(), error) {
	orig := maps.Clone(cm.Data)
	if cm.Data == nil {
		cm.Data = map[string]string{}
	}
	cm.Data[key] = value
	if err := kubeClient.Update(context.Background(), cm); err != nil {
		return nil, fmt.Errorf("patching %s %s: %w", cm.Name, key, err)
	}
	logger.Infof("patched %s %s with ts.net entry", cm.Name, key)

	name := cm.Name
	return func() {
		restore := getDNSConfigMap(context.Background(), name)
		if restore == nil {
			logger.Warnf("restoring %s %s: get failed", name, key)
			return
		}
		restore.Data = orig
		if err := kubeClient.Update(context.Background(), restore); err != nil {
			logger.Warnf("restoring %s %s: %v", name, key, err)
		}
	}, nil
}

// stripTSNetZone removes a previously-appended `ts.net:53 { ... }` server block
// from a Corefile.
func stripTSNetZone(corefile string) string {
	idx := strings.Index(corefile, "ts.net:53 {")
	if idx == -1 {
		return corefile
	}
	rest := corefile[idx:]
	end := strings.Index(rest, "\n}")
	if end == -1 {
		return corefile[:idx]
	}
	return corefile[:idx] + rest[end+len("\n}"):]
}

// forwardLocalPortToPod sets up port forwarding to the specified Pod and remote port.
// It runs until the provided ctx is done.
func forwardLocalPortToPod(ctx context.Context, logger *zap.SugaredLogger, cfg *rest.Config, ns, podName string, port int) error {
	transport, upgrader, err := spdy.RoundTripperFor(cfg)
	if err != nil {
		return fmt.Errorf("failed to create round tripper: %w", err)
	}

	u, err := url.Parse(fmt.Sprintf("%s%s/api/v1/namespaces/%s/pods/%s/portforward", cfg.Host, cfg.APIPath, ns, podName))
	if err != nil {
		return fmt.Errorf("failed to parse URL: %w", err)
	}
	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, "POST", u)

	stopChan := make(chan struct{}, 1)
	readyChan := make(chan struct{}, 1)

	ports := []string{fmt.Sprintf("%d:%d", port, port)}

	// TODO(tomhjp): work out how zap logger can be used instead of stdout/err.
	pf, err := portforward.New(dialer, ports, stopChan, readyChan, os.Stdout, os.Stderr)
	if err != nil {
		return fmt.Errorf("failed to create port forwarder: %w", err)
	}

	go func() {
		if err := pf.ForwardPorts(); err != nil {
			logger.Infof("Port forwarding error: %v\n", err)
		}
	}()

	var once sync.Once
	go func() {
		<-ctx.Done()
		once.Do(func() { close(stopChan) })
	}()

	// Wait for port forwarding to be ready
	select {
	case <-readyChan:
		logger.Infof("Port forwarding to Pod %s/%s ready", ns, podName)
	case <-time.After(10 * time.Second):
		once.Do(func() { close(stopChan) })
		return fmt.Errorf("timeout waiting for port forward to be ready")
	}

	return nil
}

// waitForPodReady waits for at least 1 Pod matching the label selector to be
// in Ready state. It returns the name of the first ready Pod it finds.
func waitForPodReady(ctx context.Context, logger *zap.SugaredLogger, cl client.WithWatch, ns string, labelSelector client.MatchingLabels) (string, error) {
	pods := &corev1.PodList{}
	w, err := cl.Watch(ctx, pods, client.InNamespace(ns), client.MatchingLabels(labelSelector))
	if err != nil {
		return "", fmt.Errorf("failed to create pod watcher: %v", err)
	}
	defer w.Stop()

	for {
		select {
		case event, ok := <-w.ResultChan():
			if !ok {
				return "", fmt.Errorf("watcher channel closed")
			}

			switch event.Type {
			case watch.Added, watch.Modified:
				if pod, ok := event.Object.(*corev1.Pod); ok {
					for _, condition := range pod.Status.Conditions {
						if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
							logger.Infof("pod %s is ready", pod.Name)
							return pod.Name, nil
						}
					}
				}
			case watch.Error:
				return "", fmt.Errorf("watch error: %v", event.Object)
			}
		case <-ctx.Done():
			return "", fmt.Errorf("timeout waiting for pod to be ready")
		}
	}
}

func pebbleGet(ctx context.Context, port uint16, path string) ([]byte, error) {
	pebbleClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: testCAs,
			},
		},
		Timeout: 10 * time.Second,
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://localhost:%d%s", port, path), nil)
	resp, err := pebbleClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch pebble root CA: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d when fetching pebble root CA", resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read pebble root CA response: %w", err)
	}

	return b, nil
}

// detectNodeArch returns the CPU architecture of the cluster's nodes.
// It uses the first node found. Mixed-architecture clusters are not
// supported.
func detectNodeArch(ctx context.Context, cl client.Client) (string, error) {
	var nodes corev1.NodeList
	if err := cl.List(ctx, &nodes); err != nil {
		return "", fmt.Errorf("listing nodes: %w", err)
	}
	if len(nodes.Items) == 0 {
		return "", fmt.Errorf("cluster has no nodes")
	}
	arch := nodes.Items[0].Status.NodeInfo.Architecture
	if arch == "" {
		return "", fmt.Errorf("node %q reports no architecture", nodes.Items[0].Name)
	}
	return arch, nil
}

func createOrUpdate(ctx context.Context, cl client.Client, obj client.Object) error {
	if err := cl.Create(ctx, obj); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return err
		}
		return cl.Update(ctx, obj)
	}
	return nil
}

// detectClusterIPFamilies determines which IP families the cluster supports by
// creating a throwaway ClusterIP Service with PreferDualStack and reading back
// the IP families the API server assigns.
func detectClusterIPFamilies(ctx context.Context, logger *zap.SugaredLogger, cl client.Client) error {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ipfamily-probe",
			Namespace: ns,
		},
		Spec: corev1.ServiceSpec{
			Type:           corev1.ServiceTypeClusterIP,
			IPFamilyPolicy: new(corev1.IPFamilyPolicyPreferDualStack),
			Ports: []corev1.ServicePort{
				{Name: "probe", Protocol: corev1.ProtocolTCP, Port: 80},
			},
		},
	}
	if err := cl.Create(ctx, svc); err != nil {
		return fmt.Errorf("failed to create IP family Service: %w", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if err := cl.Delete(ctx, svc); err != nil {
			logger.Warnf("failed to clean up IP family Service %s/%s: %v", svc.Namespace, svc.Name, err)
		}
	}()

	for _, ip := range svc.Spec.IPFamilies {
		switch ip {
		case corev1.IPv4Protocol:
			clusterIPv4Support = true
		case corev1.IPv6Protocol:
			clusterIPv6Support = true
		}
	}
	if !clusterIPv4Support && !clusterIPv6Support {
		return fmt.Errorf("Service %s/%s reported no IP families", svc.Namespace, svc.Name)
	}
	return nil
}

// createTailnet creates a new tailnet and returns a tailscale.Client
// authenticated against it using the bootstrap credentials included in the
// creation response.
func createTailnet(ctx context.Context, tsClient *tailscale.Client) (*tailscale.Client, error) {
	tailnetName := fmt.Sprintf("second-tailnet-%d", time.Now().Unix())
	body, err := json.Marshal(map[string]any{"displayName": tailnetName})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal tailnet creation request: %w", err)
	}
	// TODO(beckypauley): change to use a method on tailscale.Client once this is available.
	req, _ := http.NewRequestWithContext(ctx, "POST", tsClient.BaseURL.String()+"/api/v2/organizations/-/tailnets", bytes.NewBuffer(body))
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tsClient.APIKey))
	resp, err := tsClient.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to create tailnet: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d creating tailnet: %s", resp.StatusCode, string(b))
	}
	var result struct {
		OauthClient struct {
			ID     string `json:"id"`
			Secret string `json:"secret"`
		} `json:"oauthClient"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return tailscaleClientFromSecret(tsClient.BaseURL.String(), result.OauthClient.ID, result.OauthClient.Secret), nil
}

// tailscaleClientFromSecret returns a tailscale.Client that authenticates
// with OAuth client credentials, exchanging them for access tokens on demand.
func tailscaleClientFromSecret(baseURL, clientID, clientSecret string) *tailscale.Client {
	return &tailscale.Client{
		BaseURL: must.Get(url.Parse(baseURL)),
		Auth: &tailscale.OAuth{
			ClientID:     clientID,
			ClientSecret: clientSecret,
		},
	}
}
