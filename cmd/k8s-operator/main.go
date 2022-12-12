// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// tailscale-operator provides a way to expose services running in a Kubernetes
// cluster to your Tailnet.
package main

import (
	"context"
	_ "embed"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"golang.org/x/exp/slices"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/manager/signals"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
	"sigs.k8s.io/yaml"
	"tailscale.com/client/tailscale"
	"tailscale.com/ipn/store/kubestore"
	"tailscale.com/tsnet"
	"tailscale.com/types/logger"
)

var (
	hostname    = defaultEnv("OPERATOR_HOSTNAME", "tailscale-operator")
	kubeSecret  = defaultEnv("OPERATOR_SECRET", "")
	tsNamespace = defaultEnv("OPERATOR_NAMESPACE", "default")
	image       = defaultEnv("PROXY_IMAGE", "tailscale/tailscale:latest")
	tags        = defaultEnv("PROXY_TAGS", "tag:k8s")
)

func main() {
	// TODO: use logpolicy
	tailscale.I_Acknowledge_This_API_Is_Unstable = true
	logf.SetLogger(zap.New())
	s := &tsnet.Server{
		Hostname: hostname,
		Logf:     logger.Discard,
	}
	if kubeSecret != "" {
		st, err := kubestore.New(logger.Discard, kubeSecret)
		if err != nil {
			log.Fatalf("creating kube store: %v", err)
		}
		s.Store = st
	}
	if err := s.Start(); err != nil {
		log.Fatalf("starting tailscale server: %v", err)
	}
	defer s.Close()
	lc, err := s.LocalClient()
	if err != nil {
		log.Fatalf("getting local client: %v", err)
	}

	ctx := context.Background()
	loginShown := false
	machineAuthShown := false
waitOnline:
	for {
		st, err := lc.StatusWithoutPeers(ctx)
		if err != nil {
			log.Fatalf("getting status: %v", err)
		}
		switch st.BackendState {
		case "Running":
			break waitOnline
		case "NeedsLogin":
			if !loginShown && st.AuthURL != "" {
				log.Printf("tailscale needs login, please visit: %s", st.AuthURL)
				loginShown = true
			}
		case "NeedsMachineAuth":
			if !machineAuthShown {
				log.Printf("Machine authorization required, please visit the admin panel to authorize")
				machineAuthShown = true
			}
		default:
			log.Printf("waiting for tailscale to start: %v", st.BackendState)
		}
		time.Sleep(time.Second)
	}

	// For secrets and statefulsets, we only get permission to touch the objects
	// in the controller's own namespace. This cannot be expressed by
	// .Watches(...) below, instead you have to add a per-type field selector to
	// the cache that sits a few layers below the builder stuff, which will
	// implicitly filter what parts of the world the builder code gets to see at
	// all.
	nsFilter := cache.ObjectSelector{
		Field: fields.SelectorFromSet(fields.Set{"metadata.namespace": tsNamespace}),
	}
	mgr, err := manager.New(config.GetConfigOrDie(), manager.Options{
		NewCache: cache.BuilderWithOptions(cache.Options{
			SelectorsByObject: map[client.Object]cache.ObjectSelector{
				&corev1.Secret{}:      nsFilter,
				&appsv1.StatefulSet{}: nsFilter,
			},
		}),
	})
	if err != nil {
		log.Fatalf("could not create manager: %v", err)
	}
	tsClient, err := s.APIClient()
	if err != nil {
		log.Fatalf("getting tailscale client: %v", err)
	}
	sr := &ServiceReconciler{
		tsClient:    tsClient,
		defaultTags: strings.Split(tags, ","),
	}
	reconcileFilter := handler.EnqueueRequestsFromMapFunc(func(o client.Object) []reconcile.Request {
		ls := o.GetLabels()
		if ls[LabelManaged] != "true" {
			return nil
		}
		if ls[LabelParentType] != "svc" {
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
	err = builder.
		ControllerManagedBy(mgr).
		For(&corev1.Service{}).
		Watches(&source.Kind{Type: &appsv1.StatefulSet{}}, reconcileFilter).
		Watches(&source.Kind{Type: &corev1.Secret{}}, reconcileFilter).
		Complete(sr)
	if err != nil {
		log.Fatalf("could not create controller: %v", err)
	}

	log.Printf("Startup complete, operator running")
	if err := mgr.Start(signals.SetupSignalHandler()); err != nil {
		log.Fatalf("could not start manager: %v", err)
	}
}

const (
	LabelManaged         = "tailscale.com/managed"
	LabelParentType      = "tailscale.com/parent-resource-type"
	LabelParentName      = "tailscale.com/parent-resource"
	LabelParentNamespace = "tailscale.com/parent-resource-ns"

	FinalizerName = "tailscale.com/finalizer"

	AnnotationExpose = "tailscale.com/expose"
	AnnotationTags   = "tailscale.com/tags"
)

// ServiceReconciler is a simple ControllerManagedBy example implementation.
type ServiceReconciler struct {
	client.Client
	defaultTags []string
	tsClient    tsClient
}

type tsClient interface {
	DeleteDevice(ctx context.Context, id string) error
	Tailnet() string
	CreateKey(ctx context.Context, caps tailscale.KeyCapabilities) (string, *tailscale.Key, error)
}

func childResourceLabels(parent *corev1.Service) map[string]string {
	// You might wonder why we're using owner references, since they seem to be
	// built for exactly this. Unfortunately, Kubernetes does not support
	// cross-namespace ownership, by design. This means we cannot make the
	// service being exposed the owner of the implementation details of the
	// proxying. Instead, we have to do our own filtering and tracking with
	// labels.
	return map[string]string{
		LabelManaged:         "true",
		LabelParentName:      parent.GetName(),
		LabelParentNamespace: parent.GetNamespace(),
		LabelParentType:      "svc",
	}
}

// cleanupIfRequired removes any existing resources related to svc.
//
// This function is responsible for removing the finalizer from the service,
// once all associated resources are gone.
func (a *ServiceReconciler) cleanupIfRequired(ctx context.Context, svc *corev1.Service) (reconcile.Result, error) {
	ix := slices.Index(svc.Finalizers, FinalizerName)
	if ix < 0 {
		return reconcile.Result{}, nil
	}

	ml := childResourceLabels(svc)

	// Need to delete the StatefulSet first, and delete it with foreground
	// cascading deletion. That way, the pod that's writing to the Secret will
	// stop running before we start looking at the Secret's contents, and
	// assuming k8s ordering semantics don't mess with us, that should avoid
	// tailscale device deletion races where we fail to notice a device that
	// should be removed.
	sts, err := getSingleObject[appsv1.StatefulSet](ctx, a.Client, ml)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("getting statefulset: %w", err)
	}
	if sts != nil {
		if !sts.GetDeletionTimestamp().IsZero() {
			// Deletion in progress, check again later.
			return reconcile.Result{RequeueAfter: time.Second}, nil
		}
		err := a.DeleteAllOf(ctx, &appsv1.StatefulSet{}, client.InNamespace(tsNamespace), client.MatchingLabels(ml), client.PropagationPolicy(metav1.DeletePropagationForeground))
		if err != nil {
			return reconcile.Result{}, fmt.Errorf("deleting statefulset: %w", err)
		}
		return reconcile.Result{RequeueAfter: time.Second}, nil
	}

	id, _, err := a.getDeviceInfo(ctx, svc)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("getting device info: %w", err)
	}
	if id != "" {
		// TODO: handle case where the device is already deleted, but the secret
		// is still around.
		if err := a.tsClient.DeleteDevice(ctx, id); err != nil {
			return reconcile.Result{}, fmt.Errorf("deleting device: %w", err)
		}
	}

	types := []client.Object{
		&corev1.Service{},
		&corev1.Secret{},
	}
	for _, typ := range types {
		if err := a.DeleteAllOf(ctx, typ, client.InNamespace(tsNamespace), client.MatchingLabels(ml)); err != nil {
			return reconcile.Result{}, err
		}
	}

	svc.Finalizers = append(svc.Finalizers[:ix], svc.Finalizers[ix+1:]...)
	if err := a.Update(ctx, svc); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to remove finalizer: %w", err)
	}

	return reconcile.Result{}, nil
}

func (a *ServiceReconciler) hasLoadBalancerClass(svc *corev1.Service) bool {
	return svc != nil &&
		svc.Spec.Type == corev1.ServiceTypeLoadBalancer &&
		svc.Spec.LoadBalancerClass != nil &&
		*svc.Spec.LoadBalancerClass == "tailscale"
}

func (a *ServiceReconciler) hasAnnotation(svc *corev1.Service) bool {
	return svc != nil &&
		svc.Annotations[AnnotationExpose] == "true"
}

func (a *ServiceReconciler) shouldExpose(svc *corev1.Service) bool {
	return a.hasLoadBalancerClass(svc) || a.hasAnnotation(svc)
}

func (a *ServiceReconciler) Reconcile(ctx context.Context, req reconcile.Request) (_ reconcile.Result, err error) {
	defer func() {
		if err != nil {
			log.Printf("error reconciling %s/%s: %v", req.Namespace, req.Name, err)
		}
	}()

	svc := new(corev1.Service)
	err = a.Get(ctx, req.NamespacedName, svc)
	if err != nil {
		if apierrors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, fmt.Errorf("failed to get svc: %w", err)
	}
	if !svc.DeletionTimestamp.IsZero() || !a.shouldExpose(svc) {
		return a.cleanupIfRequired(ctx, svc)
	}

	if svc.Spec.ClusterIP == "" || svc.Spec.ClusterIP == "None" {
		log.Printf("%s has ClusterIP=%q; nothing to do", svc.Name, svc.Spec.ClusterIP)
		return reconcile.Result{}, nil
	}
	log.Printf("exposing %s", svc.Name)

	if !slices.Contains(svc.Finalizers, FinalizerName) {
		svc.Finalizers = append(svc.Finalizers, FinalizerName)
		if err := a.Update(ctx, svc); err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to add finalizer: %w", err)
		}
	}

	// Do full reconcile.
	hsvc, err := a.reconcileHeadlessService(ctx, svc)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to reconcile headless service: %w", err)
	}

	tags := a.defaultTags
	if tstr, ok := svc.Annotations[AnnotationTags]; ok {
		tags = strings.Split(tstr, ",")
	}
	secretName, err := a.createOrGetSecret(ctx, svc, hsvc, tags)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to create or get API key secret: %w", err)
	}
	_, err = a.reconcileSTS(ctx, svc, hsvc, secretName)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to reconcile statefulset: %w", err)
	}

	if !a.hasLoadBalancerClass(svc) {
		return reconcile.Result{}, nil
	}

	_, tsHost, err := a.getDeviceInfo(ctx, svc)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to get device ID: %w", err)
	}
	if tsHost == "" {
		// No hostname yet. Wait for the proxy pod to auth.
		svc.Status.LoadBalancer.Ingress = nil
		if err := a.Status().Update(ctx, svc); err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to update service status: %w", err)
		}
		return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
	}

	svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{
		{
			Hostname: tsHost,
		},
	}
	if err := a.Status().Update(ctx, svc); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to update service status: %w", err)
	}
	return reconcile.Result{}, nil
}

func (a *ServiceReconciler) reconcileHeadlessService(ctx context.Context, svc *corev1.Service) (*corev1.Service, error) {
	hsvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "ts-" + svc.Name + "-",
			Namespace:    tsNamespace,
			Labels:       childResourceLabels(svc),
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "None",
			Selector: map[string]string{
				"app": string(svc.UID),
			},
		},
	}
	return createOrUpdate(ctx, a.Client, hsvc, func(svc *corev1.Service) { svc.Spec = hsvc.Spec })
}

func (a *ServiceReconciler) createOrGetSecret(ctx context.Context, svc, hsvc *corev1.Service, tags []string) (string, error) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			// Hardcode a -0 suffix so that in future, if we support
			// multiple StatefulSet replicas, we can provision -N for
			// those.
			Name:      hsvc.Name + "-0",
			Namespace: tsNamespace,
			Labels:    childResourceLabels(svc),
		},
	}
	if err := a.Get(ctx, client.ObjectKeyFromObject(secret), secret); err == nil {
		return secret.Name, nil
	} else if !apierrors.IsNotFound(err) {
		return "", err
	}

	// Secret doesn't exist yet, create one. Initially it contains
	// only the Tailscale authkey, but once Tailscale starts it'll
	// also store the daemon state.
	sts, err := getSingleObject[appsv1.StatefulSet](ctx, a.Client, childResourceLabels(svc))
	if err != nil {
		return "", err
	}
	if sts != nil {
		// StatefulSet exists, so we have already created the secret.
		// If the secret is missing, they should delete the StatefulSet.
		return "", nil
	}
	// Create API Key secret which is going to be used by the statefulset
	// to authenticate with Tailscale.
	authKey, err := a.newAuthKey(ctx, tags)
	if err != nil {
		return "", err
	}

	secret.StringData = map[string]string{
		"authkey": authKey,
	}
	if err := a.Create(ctx, secret); err != nil {
		return "", err
	}
	return secret.Name, nil
}

func (a *ServiceReconciler) getDeviceInfo(ctx context.Context, svc *corev1.Service) (id, hostname string, err error) {
	sec, err := getSingleObject[corev1.Secret](ctx, a.Client, childResourceLabels(svc))
	if err != nil {
		return "", "", err
	}
	id = string(sec.Data["device_id"])
	if id == "" {
		return "", "", nil
	}
	// Kubernetes chokes on well-formed FQDNs with the trailing dot, so we have
	// to remove it.
	hostname = strings.TrimSuffix(string(sec.Data["device_fqdn"]), ".")
	if hostname == "" {
		return "", "", nil
	}
	return id, hostname, nil
}

type authKey struct {
	ID           string     `json:"id"`
	Key          string     `json:"key"`
	Created      time.Time  `json:"created"`
	Expires      time.Time  `json:"expires"`
	Capabilities capability `json:"capabilities"`
}

type newKeyRequest struct {
	Capabilities capability `json:"capabilities"`
}

type capability struct {
	Devices struct {
		Create struct {
			Reusable      bool
			Ephemeral     bool
			Preauthorized bool
			Tags          []string
		} `json:"create"`
	} `json:"devices"`
}

func (a *ServiceReconciler) newAuthKey(ctx context.Context, tags []string) (string, error) {
	caps := tailscale.KeyCapabilities{
		Devices: tailscale.KeyDeviceCapabilities{
			Create: tailscale.KeyDeviceCreateCapabilities{
				Reusable:      false,
				Preauthorized: true,
				Tags:          tags,
			},
		},
	}
	key, _, err := a.tsClient.CreateKey(ctx, caps)
	if err != nil {
		return "", err
	}
	return key, nil
}

//go:embed manifests/proxy.yaml
var proxyYaml []byte

func (a *ServiceReconciler) reconcileSTS(ctx context.Context, parentSvc, headlessSvc *corev1.Service, authKeySecret string) (*appsv1.StatefulSet, error) {
	var ss appsv1.StatefulSet
	if err := yaml.Unmarshal(proxyYaml, &ss); err != nil {
		return nil, fmt.Errorf("failed to unmarshal proxy spec: %w", err)
	}
	container := &ss.Spec.Template.Spec.Containers[0]
	container.Image = image
	container.Env = append(container.Env,
		corev1.EnvVar{
			Name:  "TS_DEST_IP",
			Value: parentSvc.Spec.ClusterIP,
		},
		corev1.EnvVar{
			Name:  "TS_KUBE_SECRET",
			Value: authKeySecret,
		})
	ss.ObjectMeta = metav1.ObjectMeta{
		Name:      headlessSvc.Name,
		Namespace: tsNamespace,
		Labels:    childResourceLabels(parentSvc),
	}
	ss.Spec.ServiceName = headlessSvc.Name
	ss.Spec.Selector = &metav1.LabelSelector{
		MatchLabels: map[string]string{
			"app": string(parentSvc.UID),
		},
	}
	ss.Spec.Template.ObjectMeta.Labels = map[string]string{
		"app": string(parentSvc.UID),
	}
	return createOrUpdate(ctx, a.Client, &ss, func(s *appsv1.StatefulSet) { s.Spec = ss.Spec })
}

func (a *ServiceReconciler) InjectClient(c client.Client) error {
	a.Client = c
	return nil
}

// ptrObject is a type constraint for pointer types that implement
// client.Object.
type ptrObject[T any] interface {
	client.Object
	*T
}

// createOrUpdate adds obj to the k8s cluster, unless the object already exists,
// in which case update is called to make changes to it. If update is nil, the
// existing object is returned unmodified.
//
// obj is looked up by its Name and Namespace if Name is set, otherwise it's
// looked up by labels.
func createOrUpdate[T any, O ptrObject[T]](ctx context.Context, c client.Client, obj O, update func(O)) (O, error) {
	var (
		existing O
		err      error
	)
	if obj.GetName() != "" {
		existing = new(T)
		existing.SetName(obj.GetName())
		existing.SetNamespace(obj.GetNamespace())
		err = c.Get(ctx, client.ObjectKeyFromObject(obj), existing)
	} else {
		existing, err = getSingleObject[T, O](ctx, c, obj.GetLabels())
	}
	if err == nil && existing != nil {
		if update != nil {
			update(existing)
			if err := c.Update(ctx, existing); err != nil {
				return nil, err
			}
		}
		return existing, nil
	}
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("failed to get object: %w", err)
	}
	if err := c.Create(ctx, obj); err != nil {
		return nil, err
	}
	return obj, nil
}

// getSingleObject searches for k8s objects of type T
// (e.g. corev1.Service) with the given labels, and returns
// it. Returns nil if no objects match the labels, and an error if
// more than one object matches.
func getSingleObject[T any, O ptrObject[T]](ctx context.Context, c client.Client, labels map[string]string) (O, error) {
	ret := O(new(T))
	kinds, _, err := c.Scheme().ObjectKinds(ret)
	if err != nil {
		return nil, err
	}
	if len(kinds) != 1 {
		// TODO: the runtime package apparently has a "pick the best
		// GVK" function somewhere that might be good enough?
		return nil, fmt.Errorf("more than 1 GroupVersionKind for %T", ret)
	}

	gvk := kinds[0]
	gvk.Kind += "List"
	lst := unstructured.UnstructuredList{}
	lst.SetGroupVersionKind(gvk)
	if err := c.List(ctx, &lst, client.InNamespace(tsNamespace), client.MatchingLabels(labels)); err != nil {
		return nil, err
	}

	if len(lst.Items) == 0 {
		return nil, nil
	}
	if len(lst.Items) > 1 {
		return nil, fmt.Errorf("found multiple matching %T objects", ret)
	}
	if err := c.Scheme().Convert(&lst.Items[0], ret, nil); err != nil {
		return nil, err
	}
	return ret, nil
}

func defaultEnv(envName, defVal string) string {
	v := os.Getenv(envName)
	if v == "" {
		return defVal
	}
	return v
}
