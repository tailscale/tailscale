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
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-logr/zapr"
	"go.uber.org/zap/zapcore"
	clientconfig "sigs.k8s.io/controller-runtime/pkg/client/config"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	kzap "sigs.k8s.io/controller-runtime/pkg/log/zap"
	"tailscale.com/hostinfo"
	"tailscale.com/ipn/store"
	apiproxy "tailscale.com/k8s-operator/api-proxy"
	"tailscale.com/kube/k8s-proxy/conf"
	"tailscale.com/tsnet"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	configFile := os.Getenv("TS_K8S_PROXY_CONFIG")
	if configFile == "" {
		return errors.New("TS_K8S_PROXY_CONFIG unset")
	}

	cfg, err := conf.Load(configFile)
	if err != nil {
		return fmt.Errorf("error loading config file %s: %w", configFile, err)
	}

	var opts []kzap.Opts
	if cfg.Parsed.LogLevel != nil {
		level, err := zapcore.ParseLevel(*cfg.Parsed.LogLevel)
		if err != nil {
			return fmt.Errorf("error parsing log level %q: %w", *cfg.Parsed.LogLevel, err)
		}
		opts = append(opts, kzap.Level(level))
	}
	zlog := kzap.NewRaw(opts...).Sugar()
	logf.SetLogger(zapr.NewLogger(zlog.Desugar()))
	if cfg.Parsed.App != nil {
		hostinfo.SetApp(*cfg.Parsed.App)
	}

	authMode := true
	if cfg.Parsed.KubeAPIServer != nil {
		v, ok := cfg.Parsed.KubeAPIServer.AuthMode.Get()
		if ok {
			authMode = v
		}
	}

	statePath := "mem:"
	if cfg.Parsed.State != nil {
		statePath = *cfg.Parsed.State
	} else {
		zlog.Warn("No state Secret provided; using in-memory store, which will lose state on restart")
	}
	st, err := store.New(zlog.Errorf, statePath)
	if err != nil {
		return fmt.Errorf("error creating state store: %w", err)
	}

	var authKey string
	if cfg.Parsed.AuthKey != nil {
		authKey = *cfg.Parsed.AuthKey
	}

	ts := &tsnet.Server{
		Logf:    zlog.Named("tsnet").Debugf,
		Store:   st,
		AuthKey: authKey,
	}
	if cfg.Parsed.Hostname != nil {
		ts.Hostname = *cfg.Parsed.Hostname
	}

	// Make sure we crash loop if Up doesn't complete in reasonable time.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := ts.Up(ctx); err != nil {
		return fmt.Errorf("error starting tailscale server: %w", err)
	}
	defer ts.Close()

	restConfig, err := clientconfig.GetConfig()
	if err != nil {
		return fmt.Errorf("error getting kubeconfig: %w", err)
	}
	ap, err := apiproxy.NewAPIServerProxy(zlog.Named("apiserver-proxy"), restConfig, ts, authMode)
	if err != nil {
		return fmt.Errorf("error creating api server proxy: %w", err)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		ap.Close()
	}()
	if err := ap.Run(); err != nil {
		return err
	}

	return nil
}
