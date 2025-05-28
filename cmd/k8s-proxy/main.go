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
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	kzap "sigs.k8s.io/controller-runtime/pkg/log/zap"
	"tailscale.com/hostinfo"
	"tailscale.com/ipn/store/kubestore"
	apiproxy "tailscale.com/k8s-operator/api-proxy"
	"tailscale.com/kube/kubetypes"
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
		podName = os.Getenv("POD_NAME")
	)

	if podName == "" {
		return fmt.Errorf("POD_NAME environment variable is not set")
	}

	var opts []kzap.Opts
	switch "dev" { // TODO(tomhjp): make configurable
	case "info":
		opts = append(opts, kzap.Level(zapcore.InfoLevel))
	case "debug":
		opts = append(opts, kzap.Level(zapcore.DebugLevel))
	case "dev":
		opts = append(opts, kzap.UseDevMode(true), kzap.Level(zapcore.DebugLevel))
	}
	zlog := kzap.NewRaw(opts...).Sugar()
	logf.SetLogger(zapr.NewLogger(zlog.Desugar()))
	hostinfo.SetApp(kubetypes.AppProxy) // TODO(tomhjp): Advertise auth/noauth as well?

	authMode := true // TODO(tomhjp): make configurable
	st, err := kubestore.New(logger.Discard, podName)
	if err != nil {
		return fmt.Errorf("error creating kubestore: %w", err)
	}

	ts := &tsnet.Server{
		Hostname: podName, // TODO(tomhjp): make configurable
		Logf:     zlog.Named("tailscaled").Debugf,
		Store:    st,
	}
	if _, err := ts.Up(context.Background()); err != nil {
		return fmt.Errorf("error starting tailscale server: %v", err)
	}
	defer ts.Close()

	restConfig, err := config.GetConfig()
	if err != nil {
		return fmt.Errorf("error getting kubeconfig: %w", err)
	}
	ap, err := apiproxy.NewAPIServerProxy(zlog, restConfig, ts, authMode)
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
