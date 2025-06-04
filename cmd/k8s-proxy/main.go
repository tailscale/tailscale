// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-logr/zapr"
	"go.uber.org/zap/zapcore"
	clientconfig "sigs.k8s.io/controller-runtime/pkg/client/config"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	kzap "sigs.k8s.io/controller-runtime/pkg/log/zap"
	"tailscale.com/cmd/k8s-proxy/internal/conf"
	"tailscale.com/hostinfo"
	"tailscale.com/ipn/store/kubestore"
	apiproxy "tailscale.com/k8s-operator/api-proxy"
	"tailscale.com/tsnet"
	"tailscale.com/types/logger"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	var (
		podName    = os.Getenv("POD_NAME")
		configFile = os.Getenv("TS_K8S_PROXY_CONFIG")
	)

	var cfg *conf.Config
	if configFile != "" {
		var err error
		cfg, err = conf.Load(configFile)
		if err != nil {
			return fmt.Errorf("error loading config file %s: %w", configFile, err)
		}
	}
	if podName == "" {
		return fmt.Errorf("POD_NAME environment variable is not set")
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

	st, err := kubestore.New(logger.Discard, podName)
	if err != nil {
		return fmt.Errorf("error creating kubestore: %w", err)
	}

	var authKey string
	if cfg.Parsed.AuthKey != nil {
		authKey = *cfg.Parsed.AuthKey
	}

	hostname := podName
	if cfg.Parsed.Hostname != nil {
		hostname = *cfg.Parsed.Hostname
	}

	ts := &tsnet.Server{
		Hostname: hostname,
		Logf:     zlog.Named("tsnet").Debugf,
		Store:    st,
		AuthKey:  authKey,
	}
	if _, err := ts.Up(context.Background()); err != nil {
		return fmt.Errorf("error starting tailscale server: %v", err)
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
