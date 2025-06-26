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
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"tailscale.com/hostinfo"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store"
	apiproxy "tailscale.com/k8s-operator/api-proxy"
	"tailscale.com/kube/k8s-proxy/conf"
	"tailscale.com/kube/state"
	"tailscale.com/syncs"
	"tailscale.com/tsnet"
)

func main() {
	logger := zap.Must(zap.NewProduction()).Sugar()
	defer logger.Sync()
	if err := run(logger); err != nil {
		logger.Fatal(err.Error())
	}
}

func run(logger *zap.SugaredLogger) error {
	var (
		configFile = os.Getenv("TS_K8S_PROXY_CONFIG")
		podUID     = os.Getenv("POD_UID")
	)
	if configFile == "" {
		return errors.New("TS_K8S_PROXY_CONFIG unset")
	}

	// ctx to live for the lifetime of the process.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// TODO(tomhjp): Support reloading config.
	// TODO(tomhjp): Support reading config from a Secret.
	cfg, err := conf.Load(configFile)
	if err != nil {
		return fmt.Errorf("error loading config file %q: %w", configFile, err)
	}

	if cfg.Parsed.LogLevel != nil {
		level, err := zapcore.ParseLevel(*cfg.Parsed.LogLevel)
		if err != nil {
			return fmt.Errorf("error parsing log level %q: %w", *cfg.Parsed.LogLevel, err)
		}
		logger = logger.WithOptions(zap.IncreaseLevel(level))
	}

	if cfg.Parsed.App != nil {
		hostinfo.SetApp(*cfg.Parsed.App)
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

	w, err := lc.WatchIPNBus(ctx, ipn.NotifyInitialNetMap)
	if err != nil {
		return fmt.Errorf("error watching IPN bus: %w", err)
	}
	defer w.Close()

	errs := make(chan error)
	wg := syncs.WaitGroup{}
	if podUID != "" {
		wg.Go(func() {
			err := state.KeepKeysUpdated(st, w.Next)
			if err != nil && err != ctx.Err() {
				errs <- fmt.Errorf("error keeping state keys updated: %w", err)
			}
		})
	}

	restConfig, err := getRestConfig()
	if err != nil {
		return fmt.Errorf("error getting rest config: %w", err)
	}
	authMode := true
	if cfg.Parsed.KubeAPIServer != nil {
		v, ok := cfg.Parsed.KubeAPIServer.AuthMode.Get()
		if ok {
			authMode = v
		}
	}
	ap, err := apiproxy.NewAPIServerProxy(logger.Named("apiserver-proxy"), restConfig, ts, authMode)
	if err != nil {
		return fmt.Errorf("error creating api server proxy: %w", err)
	}

	// TODO(tomhjp): Work out whether we should use TS_CERT_SHARE_MODE or not,
	// and possibly issue certs upfront here before serving.
	wg.Go(func() {
		if err := ap.Run(ctx); err != nil {
			errs <- fmt.Errorf("error running api server proxy: %w", err)
		}
	})

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err = <-errs:
		logger.Errorf("Shutting down due to error: %v", err)
	case s := <-sig:
		logger.Infof("Received %s, shutting down", s)
	}

	cancel()
	wg.Wait()

	return err
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

func getRestConfig() (*rest.Config, error) {
	restConfig, err := rest.InClusterConfig()
	if err == nil {
		return restConfig, nil
	}
	inClusterErr := fmt.Errorf("could not use in-cluster config: %w", err)

	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, nil)
	restConfig, err = clientConfig.ClientConfig()
	if err == nil {
		return restConfig, nil
	}

	return nil, errors.Join(inClusterErr, fmt.Errorf("could not use kubeconfig: %w", err))
}
