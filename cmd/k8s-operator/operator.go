// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// tailscale-operator provides a way to expose services running in a Kubernetes
// cluster to your Tailnet.
package main

import (
	"context"
	"flag"
	"os"
	"strings"
	"time"

	"github.com/go-logr/zapr"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/oauth2/clientcredentials"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	kzap "sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/manager/signals"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"tailscale.com/client/tailscale"
	"tailscale.com/hostinfo"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store/kubestore"
	"tailscale.com/tsnet"
	"tailscale.com/types/logger"
	"tailscale.com/version"
)

const (
	dnsConfigMapName = "dnsconfig"
)

type reconcilersConfig struct {
	enableDNS              bool
	logger                 *zap.SugaredLogger
	tsNamespace            string
	restConfig             *rest.Config
	tsClient               *tailscale.Client
	localAPIClient         *tailscale.LocalClient
	proxyImage             string
	proxyPriorityClassName string
	tags                   string
	tsnetServer            *tsnet.Server
}

func main() {
	// Required to use our client API. We're fine with the instability since the
	// client lives in the same repo as this code.
	tailscale.I_Acknowledge_This_API_Is_Unstable = true

	// TODO (irbekrm): make these into flags
	var (
		tsNamespace       = defaultEnv("OPERATOR_NAMESPACE", "")
		tslogging         = defaultEnv("OPERATOR_LOGGING", "info")
		image             = defaultEnv("PROXY_IMAGE", "tailscale/tailscale:latest")
		priorityClassName = defaultEnv("PROXY_PRIORITY_CLASS_NAME", "")
		tags              = defaultEnv("PROXY_TAGS", "tag:k8s")
		tsEnableDNS       bool
	)

	flag.BoolVar(&tsEnableDNS, "enable-dns", false, "If set to true, egress proxying to Tailscale services will be configured in such a way that cluster workloads will be able to use Tailscale services' MagicDNS names. (Additional manual configuration may be required and ts.net nameserver must be deployed.)")
	flag.Parse()

	var opts []kzap.Opts
	switch tslogging {
	case "info":
		opts = append(opts, kzap.Level(zapcore.InfoLevel))
	case "debug":
		opts = append(opts, kzap.Level(zapcore.DebugLevel))
	case "dev":
		opts = append(opts, kzap.UseDevMode(true), kzap.Level(zapcore.DebugLevel))
	}
	zlog := kzap.NewRaw(opts...).Sugar()
	logf.SetLogger(zapr.NewLogger(zlog.Desugar()))

	s, tsClient, localAPIClient := initTSNet(zlog)
	defer s.Close()
	restConfig := config.GetConfigOrDie()
	maybeLaunchAPIServerProxy(zlog, restConfig, s)
	rc := &reconcilersConfig{
		enableDNS:              tsEnableDNS,
		logger:                 zlog,
		tsNamespace:            tsNamespace,
		restConfig:             restConfig,
		proxyImage:             image,
		proxyPriorityClassName: priorityClassName,
		tags:                   tags,
		tsClient:               tsClient,
		localAPIClient:         localAPIClient,
		tsnetServer:            s,
	}
	startReconcilers(rc)
}

// initTSNet initializes the tsnet.Server and logs in to Tailscale. It uses the
// CLIENT_ID_FILE and CLIENT_SECRET_FILE environment variables to authenticate
// with Tailscale.
func initTSNet(zlog *zap.SugaredLogger) (*tsnet.Server, *tailscale.Client, *tailscale.LocalClient) {
	hostinfo.SetApp("k8s-operator")
	var (
		clientIDPath     = defaultEnv("CLIENT_ID_FILE", "")
		clientSecretPath = defaultEnv("CLIENT_SECRET_FILE", "")
		hostname         = defaultEnv("OPERATOR_HOSTNAME", "tailscale-operator")
		kubeSecret       = defaultEnv("OPERATOR_SECRET", "")
		operatorTags     = defaultEnv("OPERATOR_INITIAL_TAGS", "tag:k8s-operator")
	)
	startlog := zlog.Named("startup")
	if clientIDPath == "" || clientSecretPath == "" {
		startlog.Fatalf("CLIENT_ID_FILE and CLIENT_SECRET_FILE must be set")
	}
	clientID, err := os.ReadFile(clientIDPath)
	if err != nil {
		startlog.Fatalf("reading client ID %q: %v", clientIDPath, err)
	}
	clientSecret, err := os.ReadFile(clientSecretPath)
	if err != nil {
		startlog.Fatalf("reading client secret %q: %v", clientSecretPath, err)
	}
	credentials := clientcredentials.Config{
		ClientID:     string(clientID),
		ClientSecret: string(clientSecret),
		TokenURL:     "https://login.tailscale.com/api/v2/oauth/token",
	}
	tsClient := tailscale.NewClient("-", nil)
	tsClient.HTTPClient = credentials.Client(context.Background())

	s := &tsnet.Server{
		Hostname: hostname,
		Logf:     zlog.Named("tailscaled").Debugf,
	}
	if kubeSecret != "" {
		st, err := kubestore.New(logger.Discard, kubeSecret)
		if err != nil {
			startlog.Fatalf("creating kube store: %v", err)
		}
		s.Store = st
	}
	if err := s.Start(); err != nil {
		startlog.Fatalf("starting tailscale server: %v", err)
	}
	lc, err := s.LocalClient()
	if err != nil {
		startlog.Fatalf("getting local client: %v", err)
	}

	ctx := context.Background()
	loginDone := false
	machineAuthShown := false
waitOnline:
	for {
		startlog.Debugf("querying tailscaled status")
		st, err := lc.StatusWithoutPeers(ctx)
		if err != nil {
			startlog.Fatalf("getting status: %v", err)
		}
		switch st.BackendState {
		case "Running":
			break waitOnline
		case "NeedsLogin":
			if loginDone {
				break
			}
			caps := tailscale.KeyCapabilities{
				Devices: tailscale.KeyDeviceCapabilities{
					Create: tailscale.KeyDeviceCreateCapabilities{
						Reusable:      false,
						Preauthorized: true,
						Tags:          strings.Split(operatorTags, ","),
					},
				},
			}
			authkey, _, err := tsClient.CreateKey(ctx, caps)
			if err != nil {
				startlog.Fatalf("creating operator authkey: %v", err)
			}
			if err := lc.Start(ctx, ipn.Options{
				AuthKey: authkey,
			}); err != nil {
				startlog.Fatalf("starting tailscale: %v", err)
			}
			if err := lc.StartLoginInteractive(ctx); err != nil {
				startlog.Fatalf("starting login: %v", err)
			}
			startlog.Debugf("requested login by authkey")
			loginDone = true
		case "NeedsMachineAuth":
			if !machineAuthShown {
				startlog.Infof("Machine approval required, please visit the admin panel to approve")
				machineAuthShown = true
			}
		default:
			startlog.Debugf("waiting for tailscale to start: %v", st.BackendState)
		}
		time.Sleep(time.Second)
	}
	return s, tsClient, lc
}

// startReconcilers starts the controller-runtime manager and registers the
// ServiceReconciler.
func startReconcilers(config *reconcilersConfig) {
	var (
		isDefaultLoadBalancer = defaultBool("OPERATOR_DEFAULT_LOAD_BALANCER", false)
	)
	startlog := config.logger.Named("startReconcilers")
	// For secrets and statefulsets, we only get permission to touch the objects
	// in the controller's own namespace. This cannot be expressed by
	// .Watches(...) below, instead you have to add a per-type field selector to
	// the cache that sits a few layers below the builder stuff, which will
	// implicitly filter what parts of the world the builder code gets to see at
	// all.
	nsFilter := cache.ByObject{
		Field: client.InNamespace(config.tsNamespace).AsSelector(),
	}

	cacheOpts := cache.Options{
		ByObject: map[client.Object]cache.ByObject{
			&corev1.Secret{}:      nsFilter,
			&appsv1.StatefulSet{}: nsFilter,
		},
	}

	// we only need to watch ConfigMaps if ts.net DNS is enabled
	if config.enableDNS {
		tsNSCMName := cache.ByObject{
			Field: fields.SelectorFromSet(fields.Set{"metadata.name": dnsConfigMapName}),
		}

		// build cache filter for ConfigMaps. We only want to watch the one that
		// holds ts.net nameserver config + the ones that might hold cluster DNS
		// config
		cmFilter := cache.ByObject{
			Namespaces: map[string]cache.Config{
				config.tsNamespace: {
					FieldSelector: tsNSCMName.Field,
				},
			},
		}
		cacheOpts.ByObject[&corev1.ConfigMap{}] = cmFilter
	}

	mgr, err := manager.New(config.restConfig, manager.Options{
		Cache: cacheOpts,
	})
	if err != nil {
		startlog.Fatalf("could not create manager: %v", err)
	}

	reconcileFilter := handler.EnqueueRequestsFromMapFunc(func(_ context.Context, o client.Object) []reconcile.Request {
		ls := o.GetLabels()
		if ls[LabelManaged] != "true" {
			return nil
		}
		return []reconcile.Request{
			{
				NamespacedName: types.NamespacedName{
					Namespace: ls[LabelParentNamespace],
					Name:      ls[LabelParentName],
				},
			},
		}
	})
	eventRecorder := mgr.GetEventRecorderFor("tailscale-operator")
	ssr := &tailscaleSTSReconciler{
		Client:                 mgr.GetClient(),
		tsnetServer:            config.tsnetServer,
		tsClient:               config.tsClient,
		defaultTags:            strings.Split(config.tags, ","),
		operatorNamespace:      config.tsNamespace,
		proxyImage:             config.proxyImage,
		proxyPriorityClassName: config.proxyPriorityClassName,
		UseDNS:                 config.enableDNS,
	}

	hp := &hostsCMProvisioner{
		Client:         mgr.GetClient(),
		tsNamespace:    config.tsNamespace,
		localAPIClient: config.localAPIClient,
	}
	b := builder.
		ControllerManagedBy(mgr).
		For(&corev1.Service{}).
		Watches(&appsv1.StatefulSet{}, reconcileFilter).
		Watches(&corev1.Secret{}, reconcileFilter)

	if config.enableDNS {
		cmEventHandler := handler.EnqueueRequestsFromMapFunc(func(_ context.Context, o client.Object) []reconcile.Request {
			// currently we cache the hosts configmap, but do not trigger
			// reconciles if it has changed so any manual modifications to
			// it will not always be immediately overridden. Probably
			// eventually we want to do that- but make sure our reconciles
			// are not too expensive first
			return nil
		})
		b = b.Watches(&corev1.ConfigMap{}, cmEventHandler)
	}
	err = b.Complete(&ServiceReconciler{
		ssr:                   ssr,
		Client:                mgr.GetClient(),
		logger:                config.logger.Named("service-reconciler"),
		hostProvisioner:       hp,
		useDNS:                config.enableDNS,
		isDefaultLoadBalancer: isDefaultLoadBalancer,
	})
	if err != nil {
		startlog.Fatalf("could not create services controller: %v", err)
	}
	err = builder.
		ControllerManagedBy(mgr).
		For(&networkingv1.Ingress{}).
		Watches(&appsv1.StatefulSet{}, reconcileFilter).
		Watches(&corev1.Secret{}, reconcileFilter).
		Complete(&IngressReconciler{
			ssr:      ssr,
			recorder: eventRecorder,
			Client:   mgr.GetClient(),
			logger:   config.logger.Named("ingress-reconciler"),
		})
	if err != nil {
		startlog.Fatalf("could not create ingress controller: %v", err)
	}

	startlog.Infof("Startup complete, operator running, version: %s", version.Long())
	if err := mgr.Start(signals.SetupSignalHandler()); err != nil {
		startlog.Fatalf("could not start manager: %v", err)
	}
}

type tsClient interface {
	CreateKey(ctx context.Context, caps tailscale.KeyCapabilities) (string, *tailscale.Key, error)
	DeleteDevice(ctx context.Context, nodeStableID string) error
}
