// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// k8s-proxy proxies between tailnet and Kubernetes cluster traffic.
// Currently, it only supports proxying tailnet clients to the Kubernetes API
// server.
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/sync/errgroup"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/strings/slices"
	"tailscale.com/client/local"
	"tailscale.com/cmd/k8s-proxy/internal/config"
	"tailscale.com/hostinfo"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store"
	apiproxy "tailscale.com/k8s-operator/api-proxy"
	"tailscale.com/kube/certs"
	healthz "tailscale.com/kube/health"
	"tailscale.com/kube/k8s-proxy/conf"
	"tailscale.com/kube/kubetypes"
	klc "tailscale.com/kube/localclient"
	"tailscale.com/kube/metrics"
	"tailscale.com/kube/services"
	"tailscale.com/kube/state"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
)

func main() {
	encoderCfg := zap.NewProductionEncoderConfig()
	encoderCfg.EncodeTime = zapcore.RFC3339TimeEncoder
	logger := zap.Must(zap.Config{
		Level:            zap.NewAtomicLevelAt(zap.DebugLevel),
		Encoding:         "json",
		OutputPaths:      []string{"stderr"},
		ErrorOutputPaths: []string{"stderr"},
		EncoderConfig:    encoderCfg,
	}.Build()).Sugar()
	defer logger.Sync()

	if err := run(logger); err != nil {
		logger.Fatal(err.Error())
	}
}

func run(logger *zap.SugaredLogger) error {
	var (
		configPath = os.Getenv("TS_K8S_PROXY_CONFIG")
		podUID     = os.Getenv("POD_UID")
		podIP      = os.Getenv("POD_IP")
	)
	if configPath == "" {
		return errors.New("TS_K8S_PROXY_CONFIG unset")
	}

	// serveCtx to live for the lifetime of the process, only gets cancelled
	// once the Tailscale Service has been drained
	serveCtx, serveCancel := context.WithCancel(context.Background())
	defer serveCancel()

	// ctx to cancel to start the shutdown process.
	ctx, cancel := context.WithCancel(serveCtx)
	defer cancel()

	sigsChan := make(chan os.Signal, 1)
	signal.Notify(sigsChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		select {
		case <-ctx.Done():
		case s := <-sigsChan:
			logger.Infof("Received shutdown signal %s, exiting", s)
			cancel()
		}
	}()

	var group *errgroup.Group
	group, ctx = errgroup.WithContext(ctx)

	restConfig, err := getRestConfig(logger)
	if err != nil {
		return fmt.Errorf("error getting rest config: %w", err)
	}
	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("error creating Kubernetes clientset: %w", err)
	}

	// Load and watch config.
	cfgChan := make(chan *conf.Config)
	cfgLoader := config.NewConfigLoader(logger, clientset.CoreV1(), cfgChan)
	group.Go(func() error {
		return cfgLoader.WatchConfig(ctx, configPath)
	})

	// Get initial config.
	var cfg *conf.Config
	select {
	case <-ctx.Done():
		return group.Wait()
	case cfg = <-cfgChan:
	}

	if cfg.Parsed.LogLevel != nil {
		level, err := zapcore.ParseLevel(*cfg.Parsed.LogLevel)
		if err != nil {
			return fmt.Errorf("error parsing log level %q: %w", *cfg.Parsed.LogLevel, err)
		}
		logger = logger.WithOptions(zap.IncreaseLevel(level))
	}

	// TODO:(ChaosInTheCRD) This is a temporary workaround until we can set static endpoints using prefs
	if se := cfg.Parsed.StaticEndpoints; len(se) > 0 {
		logger.Debugf("setting static endpoints '%v' via TS_DEBUG_PRETENDPOINT environment variable", cfg.Parsed.StaticEndpoints)
		ses := make([]string, len(se))
		for i, e := range se {
			ses[i] = e.String()
		}

		err := os.Setenv("TS_DEBUG_PRETENDPOINT", strings.Join(ses, ","))
		if err != nil {
			return err
		}
	}

	if cfg.Parsed.App != nil {
		hostinfo.SetApp(*cfg.Parsed.App)
	}

	// TODO(tomhjp): Pass this setting directly into the store instead of using
	// environment variables.
	if cfg.Parsed.APIServerProxy != nil && cfg.Parsed.APIServerProxy.IssueCerts.EqualBool(true) {
		os.Setenv("TS_CERT_SHARE_MODE", "rw")
	} else {
		os.Setenv("TS_CERT_SHARE_MODE", "ro")
	}

	st, err := getStateStore(cfg.Parsed.State, logger)
	if err != nil {
		return err
	}

	// If Pod UID unset, assume we're running outside of a cluster/not managed
	// by the operator, so no need to set additional state keys.
	if podUID != "" {
		if err := state.SetInitialKeys(st, podUID); err != nil {
			return fmt.Errorf("error setting initial state: %w", err)
		}
	}

	var authKey string
	if cfg.Parsed.AuthKey != nil {
		authKey = *cfg.Parsed.AuthKey
	}

	ts := &tsnet.Server{
		Logf:     logger.Named("tsnet").Debugf,
		UserLogf: logger.Named("tsnet").Infof,
		Store:    st,
		AuthKey:  authKey,
	}

	if cfg.Parsed.ServerURL != nil {
		ts.ControlURL = *cfg.Parsed.ServerURL
	}

	if cfg.Parsed.Hostname != nil {
		ts.Hostname = *cfg.Parsed.Hostname
	}

	// Make sure we crash loop if Up doesn't complete in reasonable time.
	upCtx, upCancel := context.WithTimeout(ctx, time.Minute)
	defer upCancel()
	if _, err := ts.Up(upCtx); err != nil {
		return fmt.Errorf("error starting tailscale server: %w", err)
	}
	defer ts.Close()
	lc, err := ts.LocalClient()
	if err != nil {
		return fmt.Errorf("error getting local client: %w", err)
	}

	// Setup for updating state keys.
	if podUID != "" {
		group.Go(func() error {
			return state.KeepKeysUpdated(ctx, st, klc.New(lc))
		})
	}

	if cfg.Parsed.HealthCheckEnabled.EqualBool(true) || cfg.Parsed.MetricsEnabled.EqualBool(true) {
		addr := podIP
		if addr == "" {
			addr = cfg.GetLocalAddr()
		}

		addrPort := getLocalAddrPort(addr, cfg.GetLocalPort())
		mux := http.NewServeMux()
		localSrv := &http.Server{Addr: addrPort, Handler: mux}

		if cfg.Parsed.MetricsEnabled.EqualBool(true) {
			logger.Infof("Running metrics endpoint at %s/metrics", addrPort)
			metrics.RegisterMetricsHandlers(mux, lc, "")
		}

		if cfg.Parsed.HealthCheckEnabled.EqualBool(true) {
			ipV4, _ := ts.TailscaleIPs()
			hz := healthz.RegisterHealthHandlers(mux, ipV4.String(), logger.Infof)
			group.Go(func() error {
				err := hz.MonitorHealth(ctx, lc)
				if err == nil || errors.Is(err, context.Canceled) {
					return nil
				}
				return err
			})
		}

		group.Go(func() error {
			errChan := make(chan error)
			go func() {
				if err := localSrv.ListenAndServe(); err != nil {
					errChan <- err
				}
				close(errChan)
			}()

			select {
			case <-ctx.Done():
				sCtx, scancel := context.WithTimeout(serveCtx, 10*time.Second)
				defer scancel()
				return localSrv.Shutdown(sCtx)
			case err := <-errChan:
				return err
			}
		})
	}

	if v, ok := cfg.Parsed.AcceptRoutes.Get(); ok {
		_, err = lc.EditPrefs(ctx, &ipn.MaskedPrefs{
			RouteAllSet: true,
			Prefs:       ipn.Prefs{RouteAll: v},
		})
		if err != nil {
			return fmt.Errorf("error editing prefs: %w", err)
		}
	}

	// TODO(tomhjp): There seems to be a bug that on restart the device does
	// not get reassigned it's already working Service IPs unless we clear and
	// reset the serve config.
	if err := lc.SetServeConfig(ctx, &ipn.ServeConfig{}); err != nil {
		return fmt.Errorf("error clearing existing ServeConfig: %w", err)
	}

	var cm *certs.CertManager
	if shouldIssueCerts(cfg) {
		logger.Infof("Will issue TLS certs for Tailscale Service")
		cm = certs.NewCertManager(klc.New(lc), logger.Infof)
	}
	if err := setServeConfig(ctx, lc, cm, apiServerProxyService(cfg)); err != nil {
		return err
	}

	if cfg.Parsed.AdvertiseServices != nil {
		if _, err := lc.EditPrefs(ctx, &ipn.MaskedPrefs{
			AdvertiseServicesSet: true,
			Prefs: ipn.Prefs{
				AdvertiseServices: cfg.Parsed.AdvertiseServices,
			},
		}); err != nil {
			return fmt.Errorf("error setting prefs AdvertiseServices: %w", err)
		}
	}

	// Setup for the API server proxy.
	mode := kubetypes.APIServerProxyModeAuth
	if cfg.Parsed.APIServerProxy != nil && cfg.Parsed.APIServerProxy.Mode != nil {
		mode = *cfg.Parsed.APIServerProxy.Mode
	}
	ap, err := apiproxy.NewAPIServerProxy(logger.Named("apiserver-proxy"), restConfig, ts, mode, false)
	if err != nil {
		return fmt.Errorf("error creating api server proxy: %w", err)
	}

	group.Go(func() error {
		if err := ap.Run(serveCtx); err != nil {
			return fmt.Errorf("error running API server proxy: %w", err)
		}

		return nil
	})

	for {
		select {
		case <-ctx.Done():
			// Context cancelled, exit.
			logger.Info("Context cancelled, exiting")
			shutdownCtx, shutdownCancel := context.WithTimeout(serveCtx, 20*time.Second)
			unadvertiseErr := services.EnsureServicesNotAdvertised(shutdownCtx, lc, logger.Infof)
			shutdownCancel()
			serveCancel()
			return errors.Join(unadvertiseErr, group.Wait())
		case cfg = <-cfgChan:
			// Handle config reload.
			// TODO(tomhjp): Make auth mode reloadable.
			var prefs ipn.MaskedPrefs
			cfgLogger := logger
			currentPrefs, err := lc.GetPrefs(ctx)
			if err != nil {
				return fmt.Errorf("error getting current prefs: %w", err)
			}
			if !slices.Equal(currentPrefs.AdvertiseServices, cfg.Parsed.AdvertiseServices) {
				cfgLogger = cfgLogger.With("AdvertiseServices", fmt.Sprintf("%v -> %v", currentPrefs.AdvertiseServices, cfg.Parsed.AdvertiseServices))
				prefs.AdvertiseServicesSet = true
				prefs.Prefs.AdvertiseServices = cfg.Parsed.AdvertiseServices
			}
			if cfg.Parsed.Hostname != nil && *cfg.Parsed.Hostname != currentPrefs.Hostname {
				cfgLogger = cfgLogger.With("Hostname", fmt.Sprintf("%s -> %s", currentPrefs.Hostname, *cfg.Parsed.Hostname))
				prefs.HostnameSet = true
				prefs.Hostname = *cfg.Parsed.Hostname
			}
			if v, ok := cfg.Parsed.AcceptRoutes.Get(); ok && v != currentPrefs.RouteAll {
				cfgLogger = cfgLogger.With("AcceptRoutes", fmt.Sprintf("%v -> %v", currentPrefs.RouteAll, v))
				prefs.RouteAllSet = true
				prefs.Prefs.RouteAll = v
			}
			if !prefs.IsEmpty() {
				if _, err := lc.EditPrefs(ctx, &prefs); err != nil {
					return fmt.Errorf("error editing prefs: %w", err)
				}
			}
			if err := setServeConfig(ctx, lc, cm, apiServerProxyService(cfg)); err != nil {
				return fmt.Errorf("error setting serve config: %w", err)
			}

			cfgLogger.Infof("Config reloaded")
		}
	}
}

func getLocalAddrPort(addr string, port uint16) string {
	return net.JoinHostPort(addr, strconv.FormatUint(uint64(port), 10))
}

func getStateStore(path *string, logger *zap.SugaredLogger) (ipn.StateStore, error) {
	p := "mem:"
	if path != nil {
		p = *path
	} else {
		logger.Warn("No state Secret provided; using in-memory store, which will lose state on restart")
	}
	st, err := store.New(logger.Errorf, p)
	if err != nil {
		return nil, fmt.Errorf("error creating state store: %w", err)
	}

	return st, nil
}

func getRestConfig(logger *zap.SugaredLogger) (*rest.Config, error) {
	restConfig, err := rest.InClusterConfig()
	switch err {
	case nil:
		return restConfig, nil
	case rest.ErrNotInCluster:
		logger.Info("Not running in-cluster, falling back to kubeconfig")
	default:
		return nil, fmt.Errorf("error getting in-cluster config: %w", err)
	}

	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, nil)
	restConfig, err = clientConfig.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("error loading kubeconfig: %w", err)
	}

	return restConfig, nil
}

func apiServerProxyService(cfg *conf.Config) tailcfg.ServiceName {
	if cfg.Parsed.APIServerProxy != nil &&
		cfg.Parsed.APIServerProxy.Enabled.EqualBool(true) &&
		cfg.Parsed.APIServerProxy.ServiceName != nil &&
		*cfg.Parsed.APIServerProxy.ServiceName != "" {
		return tailcfg.ServiceName(*cfg.Parsed.APIServerProxy.ServiceName)
	}

	return ""
}

func shouldIssueCerts(cfg *conf.Config) bool {
	return cfg.Parsed.APIServerProxy != nil &&
		cfg.Parsed.APIServerProxy.IssueCerts.EqualBool(true)
}

// setServeConfig sets up serve config such that it's serving for the passed in
// Tailscale Service, and does nothing if it's already up to date.
func setServeConfig(ctx context.Context, lc *local.Client, cm *certs.CertManager, name tailcfg.ServiceName) error {
	existingServeConfig, err := lc.GetServeConfig(ctx)
	if err != nil {
		return fmt.Errorf("error getting existing serve config: %w", err)
	}

	// Ensure serve config is cleared if no Tailscale Service.
	if name == "" {
		if reflect.DeepEqual(*existingServeConfig, ipn.ServeConfig{}) {
			// Already up to date.
			return nil
		}

		if cm != nil {
			cm.EnsureCertLoops(ctx, &ipn.ServeConfig{})
		}
		return lc.SetServeConfig(ctx, &ipn.ServeConfig{})
	}

	status, err := lc.StatusWithoutPeers(ctx)
	if err != nil {
		return fmt.Errorf("error getting local client status: %w", err)
	}
	serviceHostPort := ipn.HostPort(fmt.Sprintf("%s.%s:443", name.WithoutPrefix(), status.CurrentTailnet.MagicDNSSuffix))

	serveConfig := ipn.ServeConfig{
		// Configure for the Service hostname.
		Services: map[tailcfg.ServiceName]*ipn.ServiceConfig{
			name: {
				TCP: map[uint16]*ipn.TCPPortHandler{
					443: {
						HTTPS: true,
					},
				},
				Web: map[ipn.HostPort]*ipn.WebServerConfig{
					serviceHostPort: {
						Handlers: map[string]*ipn.HTTPHandler{
							"/": {
								Proxy: "http://localhost:80",
							},
						},
					},
				},
			},
		},
	}

	if reflect.DeepEqual(*existingServeConfig, serveConfig) {
		// Already up to date.
		return nil
	}

	if cm != nil {
		cm.EnsureCertLoops(ctx, &serveConfig)
	}
	return lc.SetServeConfig(ctx, &serveConfig)
}
