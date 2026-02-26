// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
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
	"golang.org/x/oauth2/clientcredentials"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/cli"
	"helm.sh/helm/v3/pkg/release"
	"helm.sh/helm/v3/pkg/storage/driver"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
	"sigs.k8s.io/controller-runtime/pkg/client"
	klog "sigs.k8s.io/controller-runtime/pkg/log"
	kzap "sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/kind/pkg/cluster"
	"sigs.k8s.io/kind/pkg/cluster/nodeutils"
	"sigs.k8s.io/kind/pkg/cmd"

	"tailscale.com/internal/client/tailscale"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store/mem"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/tsnet"
)

const (
	pebbleTag       = "2.8.0"
	ns              = "default"
	tmp             = "/tmp/k8s-operator-e2e"
	kindClusterName = "k8s-operator-e2e"
)

var (
	tsClient   *tailscale.Client // For API calls to control.
	tnClient   *tsnet.Server     // For testing real tailnet traffic.
	restCfg    *rest.Config      // For constructing a client-go client if necessary.
	kubeClient client.WithWatch  // For k8s API calls.

	//go:embed certs/pebble.minica.crt
	pebbleMiniCACert []byte

	// Either nil (system) or pebble CAs if pebble is deployed for devcontrol.
	// pebble has a static "mini" CA that its ACME directory URL serves a cert
	// from, and also dynamically generates a different CA for issuing certs.
	testCAs *x509.CertPool

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
	fBuild       = flag.Bool("build", false, "if true, build and deploy the operator and container images from the current checkout; otherwise assume the operator is already set up")
)

func runTests(m *testing.M) (int, error) {
	logger := kzap.NewRaw().Sugar()
	klog.SetLogger(zapr.NewLogger(logger.Desugar()))
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	ossDir, err := gitRootDir()
	if err != nil {
		return 0, err
	}
	if err := os.MkdirAll(tmp, 0755); err != nil {
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
				cluster.CreateWithWaitForReady(5*time.Minute),
				cluster.CreateWithKubeconfigPath(kubeconfig),
				cluster.CreateWithNodeImage("kindest/node:v1.30.0"),
			); err != nil {
				return 0, fmt.Errorf("failed to create kind cluster: %w", err)
			}
		}

		if !*fSkipCleanup {
			defer kindProvider.Delete(kindClusterName, kubeconfig)
			defer os.Remove(kubeconfig)
		}
	}

	// Cluster client setup.
	restCfg, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return 0, fmt.Errorf("error loading kubeconfig: %w", err)
	}
	kubeClient, err = client.NewWithWatch(restCfg, client.Options{Scheme: tsapi.GlobalScheme})
	if err != nil {
		return 0, fmt.Errorf("error creating Kubernetes client: %w", err)
	}

	var (
		clusterLoginServer     string   // Login server from cluster Pod point of view.
		clientID, clientSecret string   // OAuth client for the operator to use.
		caPaths                []string // Extra CA cert file paths to add to images.

		certsDir string = filepath.Join(tmp, "certs") // Directory containing extra CA certs to add to images.
	)
	if *fDevcontrol {
		// Deploy pebble and get its certs.
		if err := applyPebbleResources(ctx, kubeClient); err != nil {
			return 0, fmt.Errorf("failed to apply pebble resources: %w", err)
		}
		pebblePod, err := waitForPodReady(ctx, logger, kubeClient, ns, client.MatchingLabels{"app": "pebble"})
		if err != nil {
			return 0, fmt.Errorf("pebble pod not ready: %w", err)
		}
		if err := forwardLocalPortToPod(ctx, logger, restCfg, ns, pebblePod, 15000); err != nil {
			return 0, fmt.Errorf("failed to set up port forwarding to pebble: %w", err)
		}
		testCAs = x509.NewCertPool()
		if ok := testCAs.AppendCertsFromPEM(pebbleMiniCACert); !ok {
			return 0, fmt.Errorf("failed to parse pebble minica cert")
		}
		var pebbleCAChain []byte
		for _, path := range []string{"/intermediates/0", "/roots/0"} {
			pem, err := pebbleGet(ctx, 15000, path)
			if err != nil {
				return 0, err
			}
			pebbleCAChain = append(pebbleCAChain, pem...)
		}
		if ok := testCAs.AppendCertsFromPEM(pebbleCAChain); !ok {
			return 0, fmt.Errorf("failed to parse pebble ca chain cert")
		}
		if err := os.MkdirAll(certsDir, 0755); err != nil {
			return 0, fmt.Errorf("failed to create certs dir: %w", err)
		}
		pebbleCAChainPath := filepath.Join(certsDir, "pebble-ca-chain.crt")
		if err := os.WriteFile(pebbleCAChainPath, pebbleCAChain, 0644); err != nil {
			return 0, fmt.Errorf("failed to write pebble CA chain: %w", err)
		}
		pebbleMiniCACertPath := filepath.Join(certsDir, "pebble.minica.crt")
		if err := os.WriteFile(pebbleMiniCACertPath, pebbleMiniCACert, 0644); err != nil {
			return 0, fmt.Errorf("failed to write pebble minica: %w", err)
		}
		caPaths = []string{pebbleCAChainPath, pebbleMiniCACertPath}
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
		if err := forwardLocalPortToPod(ctx, logger, restCfg, ns, pebblePod, 8055); err != nil {
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
		clusterLoginServer = fmt.Sprintf("http://%s:31544", sshServiceIP)

		b, err := os.ReadFile(filepath.Join(tmp, "api-key.json"))
		if err != nil {
			return 0, fmt.Errorf("failed to read api-key.json: %w", err)
		}
		var apiKeyData struct {
			APIKey string `json:"apiKey"`
		}
		if err := json.Unmarshal(b, &apiKeyData); err != nil {
			return 0, fmt.Errorf("failed to parse api-key.json: %w", err)
		}
		if apiKeyData.APIKey == "" {
			return 0, fmt.Errorf("api-key.json did not contain an API key")
		}

		// Finish setting up tsClient.
		tsClient = tailscale.NewClient("-", tailscale.APIKey(apiKeyData.APIKey))
		tsClient.BaseURL = "http://localhost:31544"

		// Set ACLs and create OAuth client.
		req, _ := http.NewRequest("POST", tsClient.BuildTailnetURL("acl"), bytes.NewReader(requiredACLs))
		resp, err := tsClient.Do(req)
		if err != nil {
			return 0, fmt.Errorf("failed to set ACLs: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			return 0, fmt.Errorf("HTTP %d setting ACLs: %s", resp.StatusCode, string(b))
		}
		logger.Infof("ACLs configured")

		reqBody, err := json.Marshal(map[string]any{
			"keyType":     "client",
			"scopes":      []string{"auth_keys", "devices:core", "services"},
			"tags":        []string{"tag:k8s-operator"},
			"description": "k8s-operator client for e2e tests",
		})
		if err != nil {
			return 0, fmt.Errorf("failed to marshal OAuth client creation request: %w", err)
		}
		req, _ = http.NewRequest("POST", tsClient.BuildTailnetURL("keys"), bytes.NewReader(reqBody))
		resp, err = tsClient.Do(req)
		if err != nil {
			return 0, fmt.Errorf("failed to create OAuth client: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			return 0, fmt.Errorf("HTTP %d creating OAuth client: %s", resp.StatusCode, string(b))
		}
		var key struct {
			ID  string `json:"id"`
			Key string `json:"key"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&key); err != nil {
			return 0, fmt.Errorf("failed to decode OAuth client creation response: %w", err)
		}
		clientID = key.ID
		clientSecret = key.Key
	} else {
		clientSecret = os.Getenv("TS_API_CLIENT_SECRET")
		if clientSecret == "" {
			return 0, fmt.Errorf("must use --devcontrol or set TS_API_CLIENT_SECRET to an OAuth client suitable for the operator")
		}
		// Format is "tskey-client-<id>-<random>".
		parts := strings.Split(clientSecret, "-")
		if len(parts) != 4 {
			return 0, fmt.Errorf("TS_API_CLIENT_SECRET is not valid")
		}
		clientID = parts[2]
		credentials := clientcredentials.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			TokenURL:     fmt.Sprintf("%s/api/v2/oauth/token", ipn.DefaultControlURL),
			Scopes:       []string{"auth_keys"},
		}
		tk, err := credentials.Token(ctx)
		if err != nil {
			return 0, fmt.Errorf("failed to get OAuth token: %w", err)
		}
		// An access token will last for an hour which is plenty of time for
		// the tests to run. No need for token refresh logic.
		tsClient = tailscale.NewClient("-", tailscale.APIKey(tk.AccessToken))
		tsClient.BaseURL = "http://localhost:31544"
	}

	var ossTag string
	if *fBuild {
		// TODO(tomhjp): proper support for --build=false and layering pebble certs on top of existing images.
		// TODO(tomhjp): support non-local platform.
		// TODO(tomhjp): build tsrecorder as well.

		// Build tailscale/k8s-operator, tailscale/tailscale, tailscale/k8s-proxy, with pebble CAs added.
		ossTag, err = tagForRepo(ossDir)
		if err != nil {
			return 0, err
		}
		logger.Infof("using OSS image tag: %q", ossTag)
		ossImageToTarget := map[string]string{
			"local/k8s-operator": "publishdevoperator",
			"local/tailscale":    "publishdevimage",
			"local/k8s-proxy":    "publishdevproxy",
		}
		for img, target := range ossImageToTarget {
			if err := buildImage(ctx, ossDir, img, target, ossTag, caPaths); err != nil {
				return 0, err
			}
			nodes, err := kindProvider.ListInternalNodes(kindClusterName)
			if err != nil {
				return 0, fmt.Errorf("failed to list kind nodes: %w", err)
			}
			// TODO(tomhjp): can be made more efficient and portable if we
			// stream built image tarballs straight to the node rather than
			// going via the daemon.
			// TODO(tomhjp): support --build with non-kind clusters.
			imgRef, err := name.ParseReference(fmt.Sprintf("%s:%s", img, ossTag))
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
	values := map[string]any{
		"loginServer": clusterLoginServer,
		"oauth": map[string]any{
			"clientId":     clientID,
			"clientSecret": clientSecret,
		},
		"apiServerProxyConfig": map[string]any{
			"mode": "true",
		},
		"operatorConfig": map[string]any{
			"logging": "debug",
			"extraEnv": []map[string]any{
				{
					"name":  "K8S_PROXY_IMAGE",
					"value": "local/k8s-proxy:" + ossTag,
				},
				{
					"name":  "TS_DEBUG_ACME_DIRECTORY_URL",
					"value": "https://pebble:14000/dir",
				},
			},
			"image": map[string]any{
				"repo":       "local/k8s-operator",
				"tag":        ossTag,
				"pullPolicy": "IfNotPresent",
			},
		},
		"proxyConfig": map[string]any{
			"defaultProxyClass": "default",
			"image": map[string]any{
				"repository": "local/tailscale",
				"tag":        ossTag,
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

	if err := applyDefaultProxyClass(ctx, kubeClient); err != nil {
		return 0, fmt.Errorf("failed to apply default ProxyClass: %w", err)
	}

	caps := tailscale.KeyCapabilities{}
	caps.Devices.Create.Preauthorized = true
	caps.Devices.Create.Ephemeral = true
	caps.Devices.Create.Tags = []string{"tag:k8s"}

	authKey, authKeyMeta, err := tsClient.CreateKey(ctx, caps)
	if err != nil {
		return 0, err
	}
	defer tsClient.DeleteKey(context.Background(), authKeyMeta.ID)

	tnClient = &tsnet.Server{
		ControlURL: tsClient.BaseURL,
		Hostname:   "test-proxy",
		Ephemeral:  true,
		Store:      &mem.Store{},
		AuthKey:    authKey,
	}
	_, err = tnClient.Up(ctx)
	if err != nil {
		return 0, err
	}
	defer tnClient.Close()

	return m.Run(), nil
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

// gitRootDir returns the top-level directory of the current git repo. Expects
// to be run from inside a git repo.
func gitRootDir() (string, error) {
	top, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", fmt.Errorf("failed to find git top level (not in corp git?): %w", err)
	}
	return strings.TrimSpace(string(top)), nil
}

func tagForRepo(dir string) (string, error) {
	cmd := exec.Command("git", "rev-parse", "--short", "HEAD")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get latest git tag for repo %q: %w", dir, err)
	}
	tag := strings.TrimSpace(string(out))

	// If dirty, append an extra random tag to ensure unique image tags.
	cmd = exec.Command("git", "status", "--porcelain")
	cmd.Dir = dir
	out, err = cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to check git status for repo %q: %w", dir, err)
	}
	if strings.TrimSpace(string(out)) != "" {
		tag += "-" + strings.ToLower(rand.Text())
	}

	return tag, nil
}

func applyDefaultProxyClass(ctx context.Context, cl client.Client) error {
	pc := &tsapi.ProxyClass{
		TypeMeta: metav1.TypeMeta{
			APIVersion: tsapi.SchemeGroupVersion.String(),
			Kind:       tsapi.ProxyClassKind,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
		Spec: tsapi.ProxyClassSpec{
			StatefulSet: &tsapi.StatefulSet{
				Pod: &tsapi.Pod{
					TailscaleInitContainer: &tsapi.Container{
						ImagePullPolicy: "IfNotPresent",
					},
					TailscaleContainer: &tsapi.Container{
						ImagePullPolicy: "IfNotPresent",
					},
				},
			},
		},
	}

	owner := client.FieldOwner("k8s-test")
	if err := cl.Patch(ctx, pc, client.Apply, owner); err != nil {
		return fmt.Errorf("failed to apply default ProxyClass: %w", err)
	}

	return nil
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

func buildImage(ctx context.Context, dir, repo, target, tag string, extraCACerts []string) error {
	var files []string
	for _, f := range extraCACerts {
		files = append(files, fmt.Sprintf("%s:/etc/ssl/certs/%s", f, filepath.Base(f)))
	}
	cmd := exec.CommandContext(ctx, "make", target,
		"PLATFORM=local",
		fmt.Sprintf("TAGS=%s", tag),
		fmt.Sprintf("REPO=%s", repo),
		fmt.Sprintf("FILES=%s", strings.Join(files, ",")),
	)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to build image %q: %w", target, err)
	}

	return nil
}
