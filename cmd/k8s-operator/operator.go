// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// tailscale-operator provides a way to expose services running in a Kubernetes
// cluster to your Tailnet.
package main

import (
	"context"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-logr/zapr"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/oauth2/clientcredentials"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	toolscache "k8s.io/client-go/tools/cache"
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
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tsnet"
	"tailscale.com/tstime"
	"tailscale.com/types/logger"
	"tailscale.com/version"
)

// Generate Connector and ProxyClass CustomResourceDefinition yamls from their Go types.
//go:generate go run sigs.k8s.io/controller-tools/cmd/controller-gen crd schemapatch:manifests=./deploy/crds output:dir=./deploy/crds paths=../../k8s-operator/apis/...

// Generate static manifests for deploying Tailscale operator on Kubernetes from the operator's Helm chart.
//go:generate go run tailscale.com/cmd/k8s-operator/generate staticmanifests

// Generate CRD API docs.
//go:generate go run github.com/elastic/crd-ref-docs --renderer=markdown --source-path=../../k8s-operator/apis/ --config=../../k8s-operator/api-docs-config.yaml --output-path=../../k8s-operator/api.md

func main() {
	// Required to use our client API. We're fine with the instability since the
	// client lives in the same repo as this code.
	tailscale.I_Acknowledge_This_API_Is_Unstable = true

	var (
		tsNamespace           = defaultEnv("OPERATOR_NAMESPACE", "")
		tslogging             = defaultEnv("OPERATOR_LOGGING", "info")
		image                 = defaultEnv("PROXY_IMAGE", "tailscale/tailscale:latest")
		priorityClassName     = defaultEnv("PROXY_PRIORITY_CLASS_NAME", "")
		tags                  = defaultEnv("PROXY_TAGS", "tag:k8s")
		tsFirewallMode        = defaultEnv("PROXY_FIREWALL_MODE", "")
		defaultProxyClass     = defaultEnv("PROXY_DEFAULT_CLASS", "")
		isDefaultLoadBalancer = defaultBool("OPERATOR_DEFAULT_LOAD_BALANCER", false)
	)

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

	// The operator can run either as a plain operator or it can
	// additionally act as api-server proxy
	// https://tailscale.com/kb/1236/kubernetes-operator/?q=kubernetes#accessing-the-kubernetes-control-plane-using-an-api-server-proxy.
	mode := parseAPIProxyMode()
	if mode == apiserverProxyModeDisabled {
		hostinfo.SetApp(kubetypes.AppOperator)
	} else {
		hostinfo.SetApp(kubetypes.AppAPIServerProxy)
	}

	s, tsClient := initTSNet(zlog)
	defer s.Close()
	restConfig := config.GetConfigOrDie()
	maybeLaunchAPIServerProxy(zlog, restConfig, s, mode)
	rOpts := reconcilerOpts{
		log:                           zlog,
		tsServer:                      s,
		tsClient:                      tsClient,
		tailscaleNamespace:            tsNamespace,
		restConfig:                    restConfig,
		proxyImage:                    image,
		proxyPriorityClassName:        priorityClassName,
		proxyActAsDefaultLoadBalancer: isDefaultLoadBalancer,
		proxyTags:                     tags,
		proxyFirewallMode:             tsFirewallMode,
		defaultProxyClass:             defaultProxyClass,
	}
	runReconcilers(rOpts)
}

// initTSNet initializes the tsnet.Server and logs in to Tailscale. It uses the
// CLIENT_ID_FILE and CLIENT_SECRET_FILE environment variables to authenticate
// with Tailscale.
func initTSNet(zlog *zap.SugaredLogger) (*tsnet.Server, *tailscale.Client) {
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
	tsClient.UserAgent = "tailscale-k8s-operator"
	tsClient.HTTPClient = credentials.Client(context.Background())

	s := &tsnet.Server{
		Hostname: hostname,
		Logf:     zlog.Named("tailscaled").Debugf,
	}
	if p := os.Getenv("TS_PORT"); p != "" {
		port, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			startlog.Fatalf("TS_PORT %q cannot be parsed as uint16: %v", p, err)
		}
		s.Port = uint16(port)
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
	return s, tsClient
}

// runReconcilers starts the controller-runtime manager and registers the
// ServiceReconciler. It blocks forever.
func runReconcilers(opts reconcilerOpts) {
	startlog := opts.log.Named("startReconcilers")
	// For secrets and statefulsets, we only get permission to touch the objects
	// in the controller's own namespace. This cannot be expressed by
	// .Watches(...) below, instead you have to add a per-type field selector to
	// the cache that sits a few layers below the builder stuff, which will
	// implicitly filter what parts of the world the builder code gets to see at
	// all.
	nsFilter := cache.ByObject{
		Field: client.InNamespace(opts.tailscaleNamespace).AsSelector(),
	}
	// We watch the ServiceMonitor CRD to ensure that reconcilers are re-triggered if user's workflows result in the
	// ServiceMonitor CRD applied after some of our resources that define ServiceMonitor creation. This selector
	// ensures that we only watch the ServiceMonitor CRD and that we don't cache full contents of it.
	serviceMonitorSelector := cache.ByObject{
		Field:     fields.SelectorFromSet(fields.Set{"metadata.name": serviceMonitorCRD}),
		Transform: crdTransformer(startlog),
	}
	mgrOpts := manager.Options{
		// TODO (irbekrm): stricter filtering what we watch/cache/call
		// reconcilers on. c/r by default starts a watch on any
		// resources that we GET via the controller manager's client.
		Cache: cache.Options{
			ByObject: map[client.Object]cache.ByObject{
				&corev1.Secret{}:                            nsFilter,
				&corev1.ServiceAccount{}:                    nsFilter,
				&corev1.Pod{}:                               nsFilter,
				&corev1.ConfigMap{}:                         nsFilter,
				&appsv1.StatefulSet{}:                       nsFilter,
				&appsv1.Deployment{}:                        nsFilter,
				&discoveryv1.EndpointSlice{}:                nsFilter,
				&rbacv1.Role{}:                              nsFilter,
				&rbacv1.RoleBinding{}:                       nsFilter,
				&apiextensionsv1.CustomResourceDefinition{}: serviceMonitorSelector,
			},
		},
		Scheme: tsapi.GlobalScheme,
	}
	mgr, err := manager.New(opts.restConfig, mgrOpts)
	if err != nil {
		startlog.Fatalf("could not create manager: %v", err)
	}

	svcFilter := handler.EnqueueRequestsFromMapFunc(serviceHandler)
	svcChildFilter := handler.EnqueueRequestsFromMapFunc(managedResourceHandlerForType("svc"))
	// If a ProxyClass changes, enqueue all Services labeled with that
	// ProxyClass's name.
	proxyClassFilterForSvc := handler.EnqueueRequestsFromMapFunc(proxyClassHandlerForSvc(mgr.GetClient(), startlog))

	eventRecorder := mgr.GetEventRecorderFor("tailscale-operator")
	ssr := &tailscaleSTSReconciler{
		Client:                 mgr.GetClient(),
		tsnetServer:            opts.tsServer,
		tsClient:               opts.tsClient,
		defaultTags:            strings.Split(opts.proxyTags, ","),
		operatorNamespace:      opts.tailscaleNamespace,
		proxyImage:             opts.proxyImage,
		proxyPriorityClassName: opts.proxyPriorityClassName,
		tsFirewallMode:         opts.proxyFirewallMode,
	}
	err = builder.
		ControllerManagedBy(mgr).
		Named("service-reconciler").
		Watches(&corev1.Service{}, svcFilter).
		Watches(&appsv1.StatefulSet{}, svcChildFilter).
		Watches(&corev1.Secret{}, svcChildFilter).
		Watches(&tsapi.ProxyClass{}, proxyClassFilterForSvc).
		Complete(&ServiceReconciler{
			ssr:                   ssr,
			Client:                mgr.GetClient(),
			logger:                opts.log.Named("service-reconciler"),
			isDefaultLoadBalancer: opts.proxyActAsDefaultLoadBalancer,
			recorder:              eventRecorder,
			tsNamespace:           opts.tailscaleNamespace,
			clock:                 tstime.DefaultClock{},
			defaultProxyClass:     opts.defaultProxyClass,
		})
	if err != nil {
		startlog.Fatalf("could not create service reconciler: %v", err)
	}
	ingressChildFilter := handler.EnqueueRequestsFromMapFunc(managedResourceHandlerForType("ingress"))
	// If a ProxyClassChanges, enqueue all Ingresses labeled with that
	// ProxyClass's name.
	proxyClassFilterForIngress := handler.EnqueueRequestsFromMapFunc(proxyClassHandlerForIngress(mgr.GetClient(), startlog))
	// Enque Ingress if a managed Service or backend Service associated with a tailscale Ingress changes.
	svcHandlerForIngress := handler.EnqueueRequestsFromMapFunc(serviceHandlerForIngress(mgr.GetClient(), startlog))
	err = builder.
		ControllerManagedBy(mgr).
		For(&networkingv1.Ingress{}).
		Watches(&appsv1.StatefulSet{}, ingressChildFilter).
		Watches(&corev1.Secret{}, ingressChildFilter).
		Watches(&corev1.Service{}, svcHandlerForIngress).
		Watches(&tsapi.ProxyClass{}, proxyClassFilterForIngress).
		Complete(&IngressReconciler{
			ssr:               ssr,
			recorder:          eventRecorder,
			Client:            mgr.GetClient(),
			logger:            opts.log.Named("ingress-reconciler"),
			defaultProxyClass: opts.defaultProxyClass,
		})
	if err != nil {
		startlog.Fatalf("could not create ingress reconciler: %v", err)
	}

	connectorFilter := handler.EnqueueRequestsFromMapFunc(managedResourceHandlerForType("connector"))
	// If a ProxyClassChanges, enqueue all Connectors that have
	// .spec.proxyClass set to the name of this ProxyClass.
	proxyClassFilterForConnector := handler.EnqueueRequestsFromMapFunc(proxyClassHandlerForConnector(mgr.GetClient(), startlog))
	err = builder.ControllerManagedBy(mgr).
		For(&tsapi.Connector{}).
		Watches(&appsv1.StatefulSet{}, connectorFilter).
		Watches(&corev1.Secret{}, connectorFilter).
		Watches(&tsapi.ProxyClass{}, proxyClassFilterForConnector).
		Complete(&ConnectorReconciler{
			ssr:      ssr,
			recorder: eventRecorder,
			Client:   mgr.GetClient(),
			logger:   opts.log.Named("connector-reconciler"),
			clock:    tstime.DefaultClock{},
		})
	if err != nil {
		startlog.Fatalf("could not create connector reconciler: %v", err)
	}
	// TODO (irbekrm): switch to metadata-only watches for resources whose
	// spec we don't need to inspect to reduce memory consumption.
	// https://github.com/kubernetes-sigs/controller-runtime/issues/1159
	nameserverFilter := handler.EnqueueRequestsFromMapFunc(managedResourceHandlerForType("nameserver"))
	err = builder.ControllerManagedBy(mgr).
		For(&tsapi.DNSConfig{}).
		Watches(&appsv1.Deployment{}, nameserverFilter).
		Watches(&corev1.ConfigMap{}, nameserverFilter).
		Watches(&corev1.Service{}, nameserverFilter).
		Watches(&corev1.ServiceAccount{}, nameserverFilter).
		Complete(&NameserverReconciler{
			recorder:    eventRecorder,
			tsNamespace: opts.tailscaleNamespace,
			Client:      mgr.GetClient(),
			logger:      opts.log.Named("nameserver-reconciler"),
			clock:       tstime.DefaultClock{},
		})
	if err != nil {
		startlog.Fatalf("could not create nameserver reconciler: %v", err)
	}

	egressSvcFilter := handler.EnqueueRequestsFromMapFunc(egressSvcsHandler)
	egressProxyGroupFilter := handler.EnqueueRequestsFromMapFunc(egressSvcsFromEgressProxyGroup(mgr.GetClient(), opts.log))
	err = builder.
		ControllerManagedBy(mgr).
		Named("egress-svcs-reconciler").
		Watches(&corev1.Service{}, egressSvcFilter).
		Watches(&tsapi.ProxyGroup{}, egressProxyGroupFilter).
		Complete(&egressSvcsReconciler{
			Client:      mgr.GetClient(),
			tsNamespace: opts.tailscaleNamespace,
			recorder:    eventRecorder,
			clock:       tstime.DefaultClock{},
			logger:      opts.log.Named("egress-svcs-reconciler"),
		})
	if err != nil {
		startlog.Fatalf("could not create egress Services reconciler: %v", err)
	}
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), new(corev1.Service), indexEgressProxyGroup, indexEgressServices); err != nil {
		startlog.Fatalf("failed setting up indexer for egress Services: %v", err)
	}

	egressSvcFromEpsFilter := handler.EnqueueRequestsFromMapFunc(egressSvcFromEps)
	err = builder.
		ControllerManagedBy(mgr).
		Named("egress-svcs-readiness-reconciler").
		Watches(&corev1.Service{}, egressSvcFilter).
		Watches(&discoveryv1.EndpointSlice{}, egressSvcFromEpsFilter).
		Complete(&egressSvcsReadinessReconciler{
			Client:      mgr.GetClient(),
			tsNamespace: opts.tailscaleNamespace,
			clock:       tstime.DefaultClock{},
			logger:      opts.log.Named("egress-svcs-readiness-reconciler"),
		})
	if err != nil {
		startlog.Fatalf("could not create egress Services readiness reconciler: %v", err)
	}

	epsFilter := handler.EnqueueRequestsFromMapFunc(egressEpsHandler)
	podsFilter := handler.EnqueueRequestsFromMapFunc(egressEpsFromPGPods(mgr.GetClient(), opts.tailscaleNamespace))
	secretsFilter := handler.EnqueueRequestsFromMapFunc(egressEpsFromPGStateSecrets(mgr.GetClient(), opts.tailscaleNamespace))
	epsFromExtNSvcFilter := handler.EnqueueRequestsFromMapFunc(epsFromExternalNameService(mgr.GetClient(), opts.log, opts.tailscaleNamespace))

	err = builder.
		ControllerManagedBy(mgr).
		Named("egress-eps-reconciler").
		Watches(&discoveryv1.EndpointSlice{}, epsFilter).
		Watches(&corev1.Pod{}, podsFilter).
		Watches(&corev1.Secret{}, secretsFilter).
		Watches(&corev1.Service{}, epsFromExtNSvcFilter).
		Complete(&egressEpsReconciler{
			Client:      mgr.GetClient(),
			tsNamespace: opts.tailscaleNamespace,
			logger:      opts.log.Named("egress-eps-reconciler"),
		})
	if err != nil {
		startlog.Fatalf("could not create egress EndpointSlices reconciler: %v", err)
	}

	// ProxyClass reconciler gets triggered on ServiceMonitor CRD changes to ensure that any ProxyClasses, that
	// define that a ServiceMonitor should be created, were set to invalid because the CRD did not exist get
	// reconciled if the CRD is applied at a later point.
	serviceMonitorFilter := handler.EnqueueRequestsFromMapFunc(proxyClassesWithServiceMonitor(mgr.GetClient(), opts.log))
	err = builder.ControllerManagedBy(mgr).
		For(&tsapi.ProxyClass{}).
		Watches(&apiextensionsv1.CustomResourceDefinition{}, serviceMonitorFilter).
		Complete(&ProxyClassReconciler{
			Client:   mgr.GetClient(),
			recorder: eventRecorder,
			logger:   opts.log.Named("proxyclass-reconciler"),
			clock:    tstime.DefaultClock{},
		})
	if err != nil {
		startlog.Fatal("could not create proxyclass reconciler: %v", err)
	}
	logger := startlog.Named("dns-records-reconciler-event-handlers")
	// On EndpointSlice events, if it is an EndpointSlice for an
	// ingress/egress proxy headless Service, reconcile the headless
	// Service.
	dnsRREpsOpts := handler.EnqueueRequestsFromMapFunc(dnsRecordsReconcilerEndpointSliceHandler)
	// On DNSConfig changes, reconcile all headless Services for
	// ingress/egress proxies in operator namespace.
	dnsRRDNSConfigOpts := handler.EnqueueRequestsFromMapFunc(enqueueAllIngressEgressProxySvcsInNS(opts.tailscaleNamespace, mgr.GetClient(), logger))
	// On Service events, if it is an ingress/egress proxy headless Service, reconcile it.
	dnsRRServiceOpts := handler.EnqueueRequestsFromMapFunc(dnsRecordsReconcilerServiceHandler)
	// On Ingress events, if it is a tailscale Ingress or if tailscale is the default ingress controller, reconcile the proxy
	// headless Service.
	dnsRRIngressOpts := handler.EnqueueRequestsFromMapFunc(dnsRecordsReconcilerIngressHandler(opts.tailscaleNamespace, opts.proxyActAsDefaultLoadBalancer, mgr.GetClient(), logger))
	err = builder.ControllerManagedBy(mgr).
		Named("dns-records-reconciler").
		Watches(&corev1.Service{}, dnsRRServiceOpts).
		Watches(&networkingv1.Ingress{}, dnsRRIngressOpts).
		Watches(&discoveryv1.EndpointSlice{}, dnsRREpsOpts).
		Watches(&tsapi.DNSConfig{}, dnsRRDNSConfigOpts).
		Complete(&dnsRecordsReconciler{
			Client:                mgr.GetClient(),
			tsNamespace:           opts.tailscaleNamespace,
			logger:                opts.log.Named("dns-records-reconciler"),
			isDefaultLoadBalancer: opts.proxyActAsDefaultLoadBalancer,
		})
	if err != nil {
		startlog.Fatalf("could not create DNS records reconciler: %v", err)
	}

	// Recorder reconciler.
	recorderFilter := handler.EnqueueRequestForOwner(mgr.GetScheme(), mgr.GetRESTMapper(), &tsapi.Recorder{})
	err = builder.ControllerManagedBy(mgr).
		For(&tsapi.Recorder{}).
		Watches(&appsv1.StatefulSet{}, recorderFilter).
		Watches(&corev1.ServiceAccount{}, recorderFilter).
		Watches(&corev1.Secret{}, recorderFilter).
		Watches(&rbacv1.Role{}, recorderFilter).
		Watches(&rbacv1.RoleBinding{}, recorderFilter).
		Complete(&RecorderReconciler{
			recorder:    eventRecorder,
			tsNamespace: opts.tailscaleNamespace,
			Client:      mgr.GetClient(),
			l:           opts.log.Named("recorder-reconciler"),
			clock:       tstime.DefaultClock{},
			tsClient:    opts.tsClient,
		})
	if err != nil {
		startlog.Fatalf("could not create Recorder reconciler: %v", err)
	}

	// Recorder reconciler.
	ownedByProxyGroupFilter := handler.EnqueueRequestForOwner(mgr.GetScheme(), mgr.GetRESTMapper(), &tsapi.ProxyGroup{})
	proxyClassFilterForProxyGroup := handler.EnqueueRequestsFromMapFunc(proxyClassHandlerForProxyGroup(mgr.GetClient(), startlog))
	err = builder.ControllerManagedBy(mgr).
		For(&tsapi.ProxyGroup{}).
		Watches(&appsv1.StatefulSet{}, ownedByProxyGroupFilter).
		Watches(&corev1.ServiceAccount{}, ownedByProxyGroupFilter).
		Watches(&corev1.Secret{}, ownedByProxyGroupFilter).
		Watches(&rbacv1.Role{}, ownedByProxyGroupFilter).
		Watches(&rbacv1.RoleBinding{}, ownedByProxyGroupFilter).
		Watches(&tsapi.ProxyClass{}, proxyClassFilterForProxyGroup).
		Complete(&ProxyGroupReconciler{
			recorder: eventRecorder,
			Client:   mgr.GetClient(),
			l:        opts.log.Named("proxygroup-reconciler"),
			clock:    tstime.DefaultClock{},
			tsClient: opts.tsClient,

			tsNamespace:       opts.tailscaleNamespace,
			proxyImage:        opts.proxyImage,
			defaultTags:       strings.Split(opts.proxyTags, ","),
			tsFirewallMode:    opts.proxyFirewallMode,
			defaultProxyClass: opts.defaultProxyClass,
		})
	if err != nil {
		startlog.Fatalf("could not create ProxyGroup reconciler: %v", err)
	}

	startlog.Infof("Startup complete, operator running, version: %s", version.Long())
	if err := mgr.Start(signals.SetupSignalHandler()); err != nil {
		startlog.Fatalf("could not start manager: %v", err)
	}
}

type reconcilerOpts struct {
	log                *zap.SugaredLogger
	tsServer           *tsnet.Server
	tsClient           *tailscale.Client
	tailscaleNamespace string       // namespace in which operator resources will be deployed
	restConfig         *rest.Config // config for connecting to the kube API server
	proxyImage         string       // <proxy-image-repo>:<proxy-image-tag>
	// proxyPriorityClassName isPriorityClass to be set for proxy Pods. This
	// is a legacy mechanism for cluster resource configuration options -
	// going forward use ProxyClass.
	// https://kubernetes.io/docs/concepts/scheduling-eviction/pod-priority-preemption/#priorityclass
	proxyPriorityClassName string
	// proxyTags are ACL tags to tag proxy auth keys. Multiple tags should
	// be provided as a string with comma-separated tag values. Proxy tags
	// default to tag:k8s.
	// https://tailscale.com/kb/1085/auth-keys
	proxyTags string
	// proxyActAsDefaultLoadBalancer determines whether this operator
	// instance should act as the default ingress controller when looking at
	// Ingress resources with unset ingress.spec.ingressClassName.
	// TODO (irbekrm): this setting does not respect the default
	// IngressClass.
	// https://kubernetes.io/docs/concepts/services-networking/ingress/#default-ingress-class
	// We should fix that and preferably integrate with that mechanism as
	// well - perhaps make the operator itself create the default
	// IngressClass if this is set to true.
	proxyActAsDefaultLoadBalancer bool
	// proxyFirewallMode determines whether non-userspace proxies should use
	// iptables or nftables for firewall configuration. Accepted values are
	// iptables, nftables and auto. If set to auto, proxy will automatically
	// determine which mode is supported for a given host (prefer nftables).
	// Auto is usually the best choice, unless you want to explicitly set
	// specific mode for debugging purposes.
	proxyFirewallMode string
	// defaultProxyClass is the name of the ProxyClass to use as the default
	// class for proxies that do not have a ProxyClass set.
	// this is defined by an operator env variable.
	defaultProxyClass string
}

// enqueueAllIngressEgressProxySvcsinNS returns a reconcile request for each
// ingress/egress proxy headless Service found in the provided namespace.
func enqueueAllIngressEgressProxySvcsInNS(ns string, cl client.Client, logger *zap.SugaredLogger) handler.MapFunc {
	return func(ctx context.Context, _ client.Object) []reconcile.Request {
		reqs := make([]reconcile.Request, 0)

		// Get all headless Services for proxies configured using Service.
		svcProxyLabels := map[string]string{
			LabelManaged:    "true",
			LabelParentType: "svc",
		}
		svcHeadlessSvcList := &corev1.ServiceList{}
		if err := cl.List(ctx, svcHeadlessSvcList, client.InNamespace(ns), client.MatchingLabels(svcProxyLabels)); err != nil {
			logger.Errorf("error listing headless Services for tailscale ingress/egress Services in operator namespace: %v", err)
			return nil
		}
		for _, svc := range svcHeadlessSvcList.Items {
			reqs = append(reqs, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: svc.Namespace, Name: svc.Name}})
		}

		// Get all headless Services for proxies configured using Ingress.
		ingProxyLabels := map[string]string{
			LabelManaged:    "true",
			LabelParentType: "ingress",
		}
		ingHeadlessSvcList := &corev1.ServiceList{}
		if err := cl.List(ctx, ingHeadlessSvcList, client.InNamespace(ns), client.MatchingLabels(ingProxyLabels)); err != nil {
			logger.Errorf("error listing headless Services for tailscale Ingresses in operator namespace: %v", err)
			return nil
		}
		for _, svc := range ingHeadlessSvcList.Items {
			reqs = append(reqs, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: svc.Namespace, Name: svc.Name}})
		}
		return reqs
	}
}

// dnsRecordsReconciler filters EndpointSlice events for which
// dns-records-reconciler should reconcile a headless Service. The only events
// it should reconcile are those for EndpointSlices associated with proxy
// headless Services.
func dnsRecordsReconcilerEndpointSliceHandler(ctx context.Context, o client.Object) []reconcile.Request {
	if !isManagedByType(o, "svc") && !isManagedByType(o, "ingress") {
		return nil
	}
	headlessSvcName, ok := o.GetLabels()[discoveryv1.LabelServiceName] // https://kubernetes.io/docs/concepts/services-networking/endpoint-slices/#ownership
	if !ok {
		return nil
	}
	return []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: o.GetNamespace(), Name: headlessSvcName}}}
}

// dnsRecordsReconcilerServiceHandler filters Service events for which
// dns-records-reconciler should reconcile. If the event is for a cluster
// ingress/cluster egress proxy's headless Service, returns the Service for
// reconcile.
func dnsRecordsReconcilerServiceHandler(ctx context.Context, o client.Object) []reconcile.Request {
	if isManagedByType(o, "svc") || isManagedByType(o, "ingress") {
		return []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: o.GetNamespace(), Name: o.GetName()}}}
	}
	return nil
}

// dnsRecordsReconcilerIngressHandler filters Ingress events to ensure that
// dns-records-reconciler only reconciles on tailscale Ingress events. When an
// event is observed on a tailscale Ingress, reconcile the proxy headless Service.
func dnsRecordsReconcilerIngressHandler(ns string, isDefaultLoadBalancer bool, cl client.Client, logger *zap.SugaredLogger) handler.MapFunc {
	return func(ctx context.Context, o client.Object) []reconcile.Request {
		ing, ok := o.(*networkingv1.Ingress)
		if !ok {
			return nil
		}
		if !isDefaultLoadBalancer && (ing.Spec.IngressClassName == nil || *ing.Spec.IngressClassName != "tailscale") {
			return nil
		}
		proxyResourceLabels := childResourceLabels(ing.Name, ing.Namespace, "ingress")
		headlessSvc, err := getSingleObject[corev1.Service](ctx, cl, ns, proxyResourceLabels)
		if err != nil {
			logger.Errorf("error getting headless Service from parent labels: %v", err)
			return nil
		}
		if headlessSvc == nil {
			return nil
		}
		return []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: headlessSvc.Namespace, Name: headlessSvc.Name}}}
	}
}

type tsClient interface {
	CreateKey(ctx context.Context, caps tailscale.KeyCapabilities) (string, *tailscale.Key, error)
	Device(ctx context.Context, deviceID string, fields *tailscale.DeviceFieldsOpts) (*tailscale.Device, error)
	DeleteDevice(ctx context.Context, nodeStableID string) error
}

func isManagedResource(o client.Object) bool {
	ls := o.GetLabels()
	return ls[LabelManaged] == "true"
}

func isManagedByType(o client.Object, typ string) bool {
	ls := o.GetLabels()
	return isManagedResource(o) && ls[LabelParentType] == typ
}

func parentFromObjectLabels(o client.Object) types.NamespacedName {
	ls := o.GetLabels()
	return types.NamespacedName{
		Namespace: ls[LabelParentNamespace],
		Name:      ls[LabelParentName],
	}
}

func managedResourceHandlerForType(typ string) handler.MapFunc {
	return func(_ context.Context, o client.Object) []reconcile.Request {
		if !isManagedByType(o, typ) {
			return nil
		}
		return []reconcile.Request{
			{NamespacedName: parentFromObjectLabels(o)},
		}
	}
}

// proxyClassHandlerForSvc returns a handler that, for a given ProxyClass,
// returns a list of reconcile requests for all Services labeled with
// tailscale.com/proxy-class: <proxy class name>.
func proxyClassHandlerForSvc(cl client.Client, logger *zap.SugaredLogger) handler.MapFunc {
	return func(ctx context.Context, o client.Object) []reconcile.Request {
		svcList := new(corev1.ServiceList)
		labels := map[string]string{
			LabelProxyClass: o.GetName(),
		}
		if err := cl.List(ctx, svcList, client.MatchingLabels(labels)); err != nil {
			logger.Debugf("error listing Services for ProxyClass: %v", err)
			return nil
		}
		reqs := make([]reconcile.Request, 0)
		for _, svc := range svcList.Items {
			reqs = append(reqs, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&svc)})
		}
		return reqs
	}
}

// proxyClassHandlerForIngress returns a handler that, for a given ProxyClass,
// returns a list of reconcile requests for all Ingresses labeled with
// tailscale.com/proxy-class: <proxy class name>.
func proxyClassHandlerForIngress(cl client.Client, logger *zap.SugaredLogger) handler.MapFunc {
	return func(ctx context.Context, o client.Object) []reconcile.Request {
		ingList := new(networkingv1.IngressList)
		labels := map[string]string{
			LabelProxyClass: o.GetName(),
		}
		if err := cl.List(ctx, ingList, client.MatchingLabels(labels)); err != nil {
			logger.Debugf("error listing Ingresses for ProxyClass: %v", err)
			return nil
		}
		reqs := make([]reconcile.Request, 0)
		for _, ing := range ingList.Items {
			reqs = append(reqs, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&ing)})
		}
		return reqs
	}
}

// proxyClassHandlerForConnector returns a handler that, for a given ProxyClass,
// returns a list of reconcile requests for all Connectors that have
// .spec.proxyClass set.
func proxyClassHandlerForConnector(cl client.Client, logger *zap.SugaredLogger) handler.MapFunc {
	return func(ctx context.Context, o client.Object) []reconcile.Request {
		connList := new(tsapi.ConnectorList)
		if err := cl.List(ctx, connList); err != nil {
			logger.Debugf("error listing Connectors for ProxyClass: %v", err)
			return nil
		}
		reqs := make([]reconcile.Request, 0)
		proxyClassName := o.GetName()
		for _, conn := range connList.Items {
			if conn.Spec.ProxyClass == proxyClassName {
				reqs = append(reqs, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&conn)})
			}
		}
		return reqs
	}
}

// proxyClassHandlerForConnector returns a handler that, for a given ProxyClass,
// returns a list of reconcile requests for all Connectors that have
// .spec.proxyClass set.
func proxyClassHandlerForProxyGroup(cl client.Client, logger *zap.SugaredLogger) handler.MapFunc {
	return func(ctx context.Context, o client.Object) []reconcile.Request {
		pgList := new(tsapi.ProxyGroupList)
		if err := cl.List(ctx, pgList); err != nil {
			logger.Debugf("error listing ProxyGroups for ProxyClass: %v", err)
			return nil
		}
		reqs := make([]reconcile.Request, 0)
		proxyClassName := o.GetName()
		for _, pg := range pgList.Items {
			if pg.Spec.ProxyClass == proxyClassName {
				reqs = append(reqs, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&pg)})
			}
		}
		return reqs
	}
}

// serviceHandlerForIngress returns a handler for Service events for ingress
// reconciler that ensures that if the Service associated with an event is of
// interest to the reconciler, the associated Ingress(es) gets be reconciled.
// The Services of interest are backend Services for tailscale Ingress and
// managed Services for an StatefulSet for a proxy configured for tailscale
// Ingress
func serviceHandlerForIngress(cl client.Client, logger *zap.SugaredLogger) handler.MapFunc {
	return func(ctx context.Context, o client.Object) []reconcile.Request {
		if isManagedByType(o, "ingress") {
			ingName := parentFromObjectLabels(o)
			return []reconcile.Request{{NamespacedName: ingName}}
		}
		ingList := networkingv1.IngressList{}
		if err := cl.List(ctx, &ingList, client.InNamespace(o.GetNamespace())); err != nil {
			logger.Debugf("error listing Ingresses: %v", err)
			return nil
		}
		reqs := make([]reconcile.Request, 0)
		for _, ing := range ingList.Items {
			if ing.Spec.IngressClassName == nil || *ing.Spec.IngressClassName != tailscaleIngressClassName {
				return nil
			}
			if ing.Spec.DefaultBackend != nil && ing.Spec.DefaultBackend.Service != nil && ing.Spec.DefaultBackend.Service.Name == o.GetName() {
				reqs = append(reqs, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&ing)})
			}
			for _, rule := range ing.Spec.Rules {
				if rule.HTTP == nil {
					continue
				}
				for _, path := range rule.HTTP.Paths {
					if path.Backend.Service != nil && path.Backend.Service.Name == o.GetName() {
						reqs = append(reqs, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&ing)})
					}
				}
			}
		}
		return reqs
	}
}

func serviceHandler(_ context.Context, o client.Object) []reconcile.Request {
	if _, ok := o.GetAnnotations()[AnnotationProxyGroup]; ok {
		// Do not reconcile Services for ProxyGroup.
		return nil
	}
	if isManagedByType(o, "svc") {
		// If this is a Service managed by a Service we want to enqueue its parent
		return []reconcile.Request{{NamespacedName: parentFromObjectLabels(o)}}
	}
	if isManagedResource(o) {
		// If this is a Servce managed by a resource that is not a Service, we leave it alone
		return nil
	}
	// If this is not a managed Service we want to enqueue it
	return []reconcile.Request{
		{
			NamespacedName: types.NamespacedName{
				Namespace: o.GetNamespace(),
				Name:      o.GetName(),
			},
		},
	}
}

// isMagicDNSName reports whether name is a full tailnet node FQDN (with or
// without final dot).
func isMagicDNSName(name string) bool {
	validMagicDNSName := regexp.MustCompile(`^[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+\.ts\.net\.?$`)
	return validMagicDNSName.MatchString(name)
}

// egressSvcsHandler returns accepts a Kubernetes object and returns a reconcile
// request for it , if the object is a Tailscale egress Service meant to be
// exposed on a ProxyGroup.
func egressSvcsHandler(_ context.Context, o client.Object) []reconcile.Request {
	if !isEgressSvcForProxyGroup(o) {
		return nil
	}
	return []reconcile.Request{
		{
			NamespacedName: types.NamespacedName{
				Namespace: o.GetNamespace(),
				Name:      o.GetName(),
			},
		},
	}
}

// egressEpsHandler returns accepts an EndpointSlice and, if the EndpointSlice
// is for an egress service, returns a reconcile request for it.
func egressEpsHandler(_ context.Context, o client.Object) []reconcile.Request {
	if typ := o.GetLabels()[labelSvcType]; typ != typeEgress {
		return nil
	}
	return []reconcile.Request{
		{
			NamespacedName: types.NamespacedName{
				Namespace: o.GetNamespace(),
				Name:      o.GetName(),
			},
		},
	}
}

// egressEpsFromEgressPods returns a Pod event handler that checks if Pod is a replica for a ProxyGroup and if it is,
// returns reconciler requests for all egress EndpointSlices for that ProxyGroup.
func egressEpsFromPGPods(cl client.Client, ns string) handler.MapFunc {
	return func(_ context.Context, o client.Object) []reconcile.Request {
		if v, ok := o.GetLabels()[LabelManaged]; !ok || v != "true" {
			return nil
		}
		// TODO(irbekrm): for now this is good enough as all ProxyGroups are egress. Add a type check once we
		// have ingress ProxyGroups.
		if typ := o.GetLabels()[LabelParentType]; typ != "proxygroup" {
			return nil
		}
		pg, ok := o.GetLabels()[LabelParentName]
		if !ok {
			return nil
		}
		return reconcileRequestsForPG(pg, cl, ns)
	}
}

// egressEpsFromPGStateSecrets returns a Secret event handler that checks if Secret is a state Secret for a ProxyGroup and if it is,
// returns reconciler requests for all egress EndpointSlices for that ProxyGroup.
func egressEpsFromPGStateSecrets(cl client.Client, ns string) handler.MapFunc {
	return func(_ context.Context, o client.Object) []reconcile.Request {
		if v, ok := o.GetLabels()[LabelManaged]; !ok || v != "true" {
			return nil
		}
		// TODO(irbekrm): for now this is good enough as all ProxyGroups are egress. Add a type check once we
		// have ingress ProxyGroups.
		if parentType := o.GetLabels()[LabelParentType]; parentType != "proxygroup" {
			return nil
		}
		if secretType := o.GetLabels()[labelSecretType]; secretType != "state" {
			return nil
		}
		pg, ok := o.GetLabels()[LabelParentName]
		if !ok {
			return nil
		}
		return reconcileRequestsForPG(pg, cl, ns)
	}
}

// egressSvcFromEps is an event handler for EndpointSlices. If an EndpointSlice is for an egress ExternalName Service
// meant to be exposed on a ProxyGroup, returns a reconcile request for the Service.
func egressSvcFromEps(_ context.Context, o client.Object) []reconcile.Request {
	if typ := o.GetLabels()[labelSvcType]; typ != typeEgress {
		return nil
	}
	if v, ok := o.GetLabels()[LabelManaged]; !ok || v != "true" {
		return nil
	}
	svcName, ok := o.GetLabels()[LabelParentName]
	if !ok {
		return nil
	}
	svcNs, ok := o.GetLabels()[LabelParentNamespace]
	if !ok {
		return nil
	}
	return []reconcile.Request{
		{
			NamespacedName: types.NamespacedName{
				Namespace: svcNs,
				Name:      svcName,
			},
		},
	}
}

func reconcileRequestsForPG(pg string, cl client.Client, ns string) []reconcile.Request {
	epsList := discoveryv1.EndpointSliceList{}
	if err := cl.List(context.Background(), &epsList,
		client.InNamespace(ns),
		client.MatchingLabels(map[string]string{labelProxyGroup: pg})); err != nil {
		return nil
	}
	reqs := make([]reconcile.Request, 0)
	for _, ep := range epsList.Items {
		reqs = append(reqs, reconcile.Request{
			NamespacedName: types.NamespacedName{
				Namespace: ep.Namespace,
				Name:      ep.Name,
			},
		})
	}
	return reqs
}

// egressSvcsFromEgressProxyGroup is an event handler for egress ProxyGroups. It returns reconcile requests for all
// user-created ExternalName Services that should be exposed on this ProxyGroup.
func egressSvcsFromEgressProxyGroup(cl client.Client, logger *zap.SugaredLogger) handler.MapFunc {
	return func(_ context.Context, o client.Object) []reconcile.Request {
		pg, ok := o.(*tsapi.ProxyGroup)
		if !ok {
			logger.Infof("[unexpected] ProxyGroup handler triggered for an object that is not a ProxyGroup")
			return nil
		}
		if pg.Spec.Type != tsapi.ProxyGroupTypeEgress {
			return nil
		}
		svcList := &corev1.ServiceList{}
		if err := cl.List(context.Background(), svcList, client.MatchingFields{indexEgressProxyGroup: pg.Name}); err != nil {
			logger.Infof("error listing Services: %v, skipping a reconcile for event on ProxyGroup %s", err, pg.Name)
			return nil
		}
		reqs := make([]reconcile.Request, 0)
		for _, svc := range svcList.Items {
			reqs = append(reqs, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Namespace: svc.Namespace,
					Name:      svc.Name,
				},
			})
		}
		return reqs
	}
}

// epsFromExternalNameService is an event handler for ExternalName Services that define a Tailscale egress service that
// should be exposed on a ProxyGroup. It returns reconcile requests for EndpointSlices created for this Service.
func epsFromExternalNameService(cl client.Client, logger *zap.SugaredLogger, ns string) handler.MapFunc {
	return func(_ context.Context, o client.Object) []reconcile.Request {
		svc, ok := o.(*corev1.Service)
		if !ok {
			logger.Infof("[unexpected] Service handler triggered for an object that is not a Service")
			return nil
		}
		if !isEgressSvcForProxyGroup(svc) {
			return nil
		}
		epsList := &discoveryv1.EndpointSliceList{}
		if err := cl.List(context.Background(), epsList, client.InNamespace(ns),
			client.MatchingLabels(egressSvcChildResourceLabels(svc))); err != nil {
			logger.Infof("error listing EndpointSlices: %v, skipping a reconcile for event on Service %s", err, svc.Name)
			return nil
		}
		reqs := make([]reconcile.Request, 0)
		for _, eps := range epsList.Items {
			reqs = append(reqs, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Namespace: eps.Namespace,
					Name:      eps.Name,
				},
			})
		}
		return reqs
	}
}

// proxyClassesWithServiceMonitor returns an event handler that, given that the event is for the Prometheus
// ServiceMonitor CRD, returns all ProxyClasses that define that a ServiceMonitor should be created.
func proxyClassesWithServiceMonitor(cl client.Client, logger *zap.SugaredLogger) handler.MapFunc {
	return func(ctx context.Context, o client.Object) []reconcile.Request {
		crd, ok := o.(*apiextensionsv1.CustomResourceDefinition)
		if !ok {
			logger.Debugf("[unexpected] ServiceMonitor CRD handler received an object that is not a CustomResourceDefinition")
			return nil
		}
		if crd.Name != serviceMonitorCRD {
			logger.Debugf("[unexpected] ServiceMonitor CRD handler received an unexpected CRD %q", crd.Name)
			return nil
		}
		pcl := &tsapi.ProxyClassList{}
		if err := cl.List(ctx, pcl); err != nil {
			logger.Debugf("[unexpected] error listing ProxyClasses: %v", err)
			return nil
		}
		reqs := make([]reconcile.Request, 0)
		for _, pc := range pcl.Items {
			if pc.Spec.Metrics != nil && pc.Spec.Metrics.ServiceMonitor != nil && pc.Spec.Metrics.ServiceMonitor.Enable {
				reqs = append(reqs, reconcile.Request{
					NamespacedName: types.NamespacedName{Namespace: pc.Namespace, Name: pc.Name},
				})
			}
		}
		return reqs
	}
}

// crdTransformer gets called before a CRD is stored to c/r cache, it removes the CRD spec to reduce memory consumption.
func crdTransformer(log *zap.SugaredLogger) toolscache.TransformFunc {
	return func(o any) (any, error) {
		crd, ok := o.(*apiextensionsv1.CustomResourceDefinition)
		if !ok {
			log.Infof("[unexpected] CRD transformer called for a non-CRD type")
			return crd, nil
		}
		crd.Spec = apiextensionsv1.CustomResourceDefinitionSpec{}
		return crd, nil
	}
}

// indexEgressServices adds a local index to a cached Tailscale egress Services meant to be exposed on a ProxyGroup. The
// index is used a list filter.
func indexEgressServices(o client.Object) []string {
	if !isEgressSvcForProxyGroup(o) {
		return nil
	}
	return []string{o.GetAnnotations()[AnnotationProxyGroup]}
}
