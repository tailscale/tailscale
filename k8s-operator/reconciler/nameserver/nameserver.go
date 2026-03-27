// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// Package nameserver provides reconciliation logic for the DNSConfig custom resource definition.
// It is responsible for creating and managing nameserver resources in response to DNSConfig objects.
package nameserver

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/yaml"

	tsoperator "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/k8s-operator/reconciler"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tstime"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/set"
)

const (
	reconcilerName = "nameserver-reconciler"

	reasonNameserverCreationFailed  = "NameserverCreationFailed"
	reasonMultipleDNSConfigsPresent = "MultipleDNSConfigsPresent"

	// ReasonNameserverCreated is the condition reason set when nameserver resources have been created successfully.
	ReasonNameserverCreated = "NameserverCreated"

	messageNameserverCreationFailed  = "Failed creating nameserver resources: %v"
	messageMultipleDNSConfigsPresent = "Multiple DNSConfig resources found in cluster. Please ensure no more than one is present."

	defaultNameserverImageRepo = "tailscale/k8s-nameserver"
	defaultNameserverImageTag  = "stable"

	optimisticLockErrorMsg = "the object has been modified; please apply your changes to the latest version and try again"
)

var gaugeNameserverResources = clientmetric.NewGauge(kubetypes.MetricNameserverCount)

// ReconcilerOptions contains the options for creating a new Reconciler.
type ReconcilerOptions struct {
	Client             client.Client
	Recorder           record.EventRecorder
	TailscaleNamespace string
	Logger             *zap.SugaredLogger
	Clock              tstime.Clock
}

// Reconciler knows how to create nameserver resources in cluster in
// response to users applying DNSConfig.
type Reconciler struct {
	client.Client
	logger      *zap.SugaredLogger
	recorder    record.EventRecorder
	clock       tstime.Clock
	tsNamespace string

	mu                 sync.Mutex           // protects following
	managedNameservers set.Slice[types.UID] // one or none
}

// NewReconciler creates a new Reconciler.
func NewReconciler(options ReconcilerOptions) *Reconciler {
	return &Reconciler{
		Client:      options.Client,
		recorder:    options.Recorder,
		tsNamespace: options.TailscaleNamespace,
		logger:      options.Logger.Named(reconcilerName),
		clock:       options.Clock,
	}
}

// Register registers the nameserver reconciler with the controller manager.
func (r *Reconciler) Register(mgr manager.Manager) error {
	nameserverFilter := handler.EnqueueRequestsFromMapFunc(reconciler.ManagedResourceHandlerForType("nameserver"))
	return builder.ControllerManagedBy(mgr).
		For(&tsapi.DNSConfig{}).
		Named(reconcilerName).
		Watches(&appsv1.Deployment{}, nameserverFilter).
		Watches(&corev1.ConfigMap{}, nameserverFilter).
		Watches(&corev1.Service{}, nameserverFilter).
		Watches(&corev1.ServiceAccount{}, nameserverFilter).
		Complete(r)
}

func (r *Reconciler) Reconcile(ctx context.Context, req reconcile.Request) (res reconcile.Result, err error) {
	logger := r.logger.With("dnsConfig", req.Name)
	logger.Debugf("starting reconcile")
	defer logger.Debugf("reconcile finished")

	var dnsCfg tsapi.DNSConfig
	err = r.Get(ctx, req.NamespacedName, &dnsCfg)
	if apierrors.IsNotFound(err) {
		// Request object not found, could have been deleted after reconcile request.
		logger.Debugf("dnsconfig not found, assuming it was deleted")
		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to get dnsconfig: %w", err)
	}
	if !dnsCfg.DeletionTimestamp.IsZero() {
		ix := slices.Index(dnsCfg.Finalizers, reconciler.FinalizerName)
		if ix < 0 {
			logger.Debugf("no finalizer, nothing to do")
			return reconcile.Result{}, nil
		}
		logger.Info("Cleaning up DNSConfig resources")
		if err := r.maybeCleanup(&dnsCfg); err != nil {
			logger.Errorf("error cleaning up reconciler resource: %v", err)
			return res, err
		}
		dnsCfg.Finalizers = append(dnsCfg.Finalizers[:ix], dnsCfg.Finalizers[ix+1:]...)
		if err := r.Update(ctx, &dnsCfg); err != nil {
			logger.Errorf("error removing finalizer: %v", err)
			return reconcile.Result{}, err
		}
		logger.Infof("Nameserver resources cleaned up")
		return reconcile.Result{}, nil
	}

	oldCnStatus := dnsCfg.Status.DeepCopy()
	setStatus := func(dnsCfg *tsapi.DNSConfig, status metav1.ConditionStatus, reason, message string) (reconcile.Result, error) {
		tsoperator.SetDNSConfigCondition(dnsCfg, tsapi.NameserverReady, status, reason, message, dnsCfg.Generation, r.clock, logger)
		if !apiequality.Semantic.DeepEqual(oldCnStatus, &dnsCfg.Status) {
			// An error encountered here should get returned by the Reconcile function.
			if updateErr := r.Client.Status().Update(ctx, dnsCfg); updateErr != nil {
				err = errors.Join(err, updateErr)
			}
		}
		return res, err
	}
	var dnsCfgs tsapi.DNSConfigList
	if err := r.List(ctx, &dnsCfgs); err != nil {
		return res, fmt.Errorf("error listing DNSConfigs: %w", err)
	}
	if len(dnsCfgs.Items) > 1 { // enforce DNSConfig to be a singleton
		msg := "invalid cluster configuration: more than one tailscale.com/dnsconfigs found. Please ensure that no more than one is created."
		logger.Error(msg)
		r.recorder.Event(&dnsCfg, corev1.EventTypeWarning, reasonMultipleDNSConfigsPresent, messageMultipleDNSConfigsPresent)
		setStatus(&dnsCfg, metav1.ConditionFalse, reasonMultipleDNSConfigsPresent, messageMultipleDNSConfigsPresent)
	}

	if !slices.Contains(dnsCfg.Finalizers, reconciler.FinalizerName) {
		logger.Infof("ensuring nameserver resources")
		dnsCfg.Finalizers = append(dnsCfg.Finalizers, reconciler.FinalizerName)
		if err := r.Update(ctx, &dnsCfg); err != nil {
			msg := fmt.Sprintf(messageNameserverCreationFailed, err)
			logger.Error(msg)
			return setStatus(&dnsCfg, metav1.ConditionFalse, reasonNameserverCreationFailed, msg)
		}
	}
	if err = r.maybeProvision(ctx, &dnsCfg); err != nil {
		if strings.Contains(err.Error(), optimisticLockErrorMsg) {
			logger.Infof("optimistic lock error, retrying: %s", err)
			return reconcile.Result{}, nil
		} else {
			return reconcile.Result{}, fmt.Errorf("error provisioning nameserver resources: %w", err)
		}
	}

	r.mu.Lock()
	r.managedNameservers.Add(dnsCfg.UID)
	r.mu.Unlock()
	gaugeNameserverResources.Set(int64(r.managedNameservers.Len()))

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "nameserver", Namespace: r.tsNamespace},
	}
	if err := r.Client.Get(ctx, client.ObjectKeyFromObject(svc), svc); err != nil {
		return res, fmt.Errorf("error getting Service: %w", err)
	}
	if ip := svc.Spec.ClusterIP; ip != "" && ip != "None" {
		dnsCfg.Status.Nameserver = &tsapi.NameserverStatus{
			IP: ip,
		}
		return setStatus(&dnsCfg, metav1.ConditionTrue, ReasonNameserverCreated, ReasonNameserverCreated)
	}
	logger.Info("nameserver Service does not have an IP address allocated, waiting...")
	return reconcile.Result{}, nil
}

func nameserverResourceLabels(name, namespace string) map[string]string {
	labels := reconciler.ChildResourceLabels(name, namespace, "nameserver")
	labels["app.kubernetes.io/name"] = "tailscale"
	labels["app.kubernetes.io/component"] = "nameserver"
	return labels
}

func (r *Reconciler) maybeProvision(ctx context.Context, tsDNSCfg *tsapi.DNSConfig) error {
	labels := nameserverResourceLabels(tsDNSCfg.Name, r.tsNamespace)
	dCfg := &deployConfig{
		ownerRefs: []metav1.OwnerReference{*metav1.NewControllerRef(tsDNSCfg, tsapi.SchemeGroupVersion.WithKind("DNSConfig"))},
		namespace: r.tsNamespace,
		labels:    labels,
		imageRepo: defaultNameserverImageRepo,
		imageTag:  defaultNameserverImageTag,
		replicas:  1,
	}

	if tsDNSCfg.Spec.Nameserver.Replicas != nil {
		dCfg.replicas = *tsDNSCfg.Spec.Nameserver.Replicas
	}
	if tsDNSCfg.Spec.Nameserver.Image != nil && tsDNSCfg.Spec.Nameserver.Image.Repo != "" {
		dCfg.imageRepo = tsDNSCfg.Spec.Nameserver.Image.Repo
	}
	if tsDNSCfg.Spec.Nameserver.Image != nil && tsDNSCfg.Spec.Nameserver.Image.Tag != "" {
		dCfg.imageTag = tsDNSCfg.Spec.Nameserver.Image.Tag
	}
	if tsDNSCfg.Spec.Nameserver.Service != nil {
		dCfg.clusterIP = tsDNSCfg.Spec.Nameserver.Service.ClusterIP
	}
	if tsDNSCfg.Spec.Nameserver.Pod != nil {
		dCfg.tolerations = tsDNSCfg.Spec.Nameserver.Pod.Tolerations
	}

	for _, d := range []deployable{saDeployable, deployDeployable, svcDeployable, cmDeployable} {
		if err := d.updateObj(ctx, dCfg, r.Client); err != nil {
			return fmt.Errorf("error reconciling %s: %w", d.kind, err)
		}
	}
	return nil
}

// maybeCleanup removes DNSConfig from being tracked. The cluster resources
// created will be automatically garbage collected as they are owned by the
// DNSConfig.
func (r *Reconciler) maybeCleanup(dnsCfg *tsapi.DNSConfig) error {
	r.mu.Lock()
	r.managedNameservers.Remove(dnsCfg.UID)
	r.mu.Unlock()
	gaugeNameserverResources.Set(int64(r.managedNameservers.Len()))
	return nil
}

type deployable struct {
	kind      string
	updateObj func(context.Context, *deployConfig, client.Client) error
}

type deployConfig struct {
	replicas    int32
	imageRepo   string
	imageTag    string
	labels      map[string]string
	ownerRefs   []metav1.OwnerReference
	namespace   string
	clusterIP   string
	tolerations []corev1.Toleration
}

var (
	//go:embed manifests/cm.yaml
	cmYaml []byte
	//go:embed manifests/deploy.yaml
	deployYaml []byte
	//go:embed manifests/sa.yaml
	saYaml []byte
	//go:embed manifests/svc.yaml
	svcYaml []byte

	deployDeployable = deployable{
		kind: "Deployment",
		updateObj: func(ctx context.Context, cfg *deployConfig, kubeClient client.Client) error {
			d := new(appsv1.Deployment)
			if err := yaml.Unmarshal(deployYaml, &d); err != nil {
				return fmt.Errorf("error unmarshalling Deployment yaml: %w", err)
			}
			d.Spec.Replicas = new(cfg.replicas)
			d.Spec.Template.Spec.Containers[0].Image = fmt.Sprintf("%s:%s", cfg.imageRepo, cfg.imageTag)
			d.ObjectMeta.Namespace = cfg.namespace
			d.ObjectMeta.Labels = cfg.labels
			d.ObjectMeta.OwnerReferences = cfg.ownerRefs
			d.Spec.Template.Spec.Tolerations = cfg.tolerations
			updateF := func(oldD *appsv1.Deployment) {
				oldD.Spec = d.Spec
			}
			_, err := createOrUpdate[appsv1.Deployment](ctx, kubeClient, cfg.namespace, d, updateF)
			return err
		},
	}
	saDeployable = deployable{
		kind: "ServiceAccount",
		updateObj: func(ctx context.Context, cfg *deployConfig, kubeClient client.Client) error {
			sa := new(corev1.ServiceAccount)
			if err := yaml.Unmarshal(saYaml, &sa); err != nil {
				return fmt.Errorf("error unmarshalling ServiceAccount yaml: %w", err)
			}
			sa.ObjectMeta.Labels = cfg.labels
			sa.ObjectMeta.OwnerReferences = cfg.ownerRefs
			sa.ObjectMeta.Namespace = cfg.namespace
			_, err := createOrUpdate(ctx, kubeClient, cfg.namespace, sa, func(*corev1.ServiceAccount) {})
			return err
		},
	}
	svcDeployable = deployable{
		kind: "Service",
		updateObj: func(ctx context.Context, cfg *deployConfig, kubeClient client.Client) error {
			svc := new(corev1.Service)
			if err := yaml.Unmarshal(svcYaml, &svc); err != nil {
				return fmt.Errorf("error unmarshalling Service yaml: %w", err)
			}
			svc.ObjectMeta.Labels = cfg.labels
			svc.ObjectMeta.OwnerReferences = cfg.ownerRefs
			svc.ObjectMeta.Namespace = cfg.namespace
			svc.Spec.ClusterIP = cfg.clusterIP
			_, err := createOrUpdate[corev1.Service](ctx, kubeClient, cfg.namespace, svc, func(*corev1.Service) {})
			return err
		},
	}
	cmDeployable = deployable{
		kind: "ConfigMap",
		updateObj: func(ctx context.Context, cfg *deployConfig, kubeClient client.Client) error {
			cm := new(corev1.ConfigMap)
			if err := yaml.Unmarshal(cmYaml, &cm); err != nil {
				return fmt.Errorf("error unmarshalling ConfigMap yaml: %w", err)
			}
			cm.ObjectMeta.Labels = cfg.labels
			cm.ObjectMeta.OwnerReferences = cfg.ownerRefs
			cm.ObjectMeta.Namespace = cfg.namespace
			_, err := createOrUpdate[corev1.ConfigMap](ctx, kubeClient, cfg.namespace, cm, func(cm *corev1.ConfigMap) {})
			return err
		},
	}
)

type ptrObject[T any] interface {
	client.Object
	*T
}

// createOrMaybeUpdate adds obj to the k8s cluster, unless the object already exists,
// in which case update is called to make changes to it. If update is nil or returns
// an error, the object is returned unmodified.
//
// obj is looked up by its Name and Namespace if Name is set, otherwise it's
// looked up by labels.
func createOrMaybeUpdate[T any, O ptrObject[T]](ctx context.Context, c client.Client, ns string, obj O, update func(O) error) (O, error) {
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
		existing, err = getSingleObject[T, O](ctx, c, ns, obj.GetLabels())
	}
	if err == nil && existing != nil {
		if update != nil {
			if err := update(existing); err != nil {
				return nil, err
			}
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

// createOrUpdate adds obj to the k8s cluster, unless the object already exists,
// in which case update is called to make changes to it. If update is nil, the
// existing object is returned unmodified.
//
// obj is looked up by its Name and Namespace if Name is set, otherwise it's
// looked up by labels.
func createOrUpdate[T any, O ptrObject[T]](ctx context.Context, c client.Client, ns string, obj O, update func(O)) (O, error) {
	return createOrMaybeUpdate(ctx, c, ns, obj, func(o O) error {
		if update != nil {
			update(o)
		}
		return nil
	})
}

// getSingleObject searches for k8s objects of type T with the given labels,
// and returns it. Returns nil if no objects match the labels, and an error if
// more than one object matches.
func getSingleObject[T any, O ptrObject[T]](ctx context.Context, c client.Client, ns string, labels map[string]string) (O, error) {
	ret := O(new(T))
	kinds, _, err := c.Scheme().ObjectKinds(ret)
	if err != nil {
		return nil, err
	}
	if len(kinds) != 1 {
		return nil, fmt.Errorf("more than 1 GroupVersionKind for %T", ret)
	}

	gvk := kinds[0]
	gvk.Kind += "List"
	lst := unstructured.UnstructuredList{}
	lst.SetGroupVersionKind(gvk)
	if err := c.List(ctx, &lst, client.InNamespace(ns), client.MatchingLabels(labels)); err != nil {
		return nil, err
	}

	if len(lst.Items) == 0 {
		return nil, nil
	}
	if len(lst.Items) > 1 {
		return nil, fmt.Errorf("found multiple matching %T objects", ret)
	}

	item := lst.Items[0]
	ret2 := O(new(T))
	if err := c.Scheme().Convert(&item, ret2, nil); err != nil {
		return nil, err
	}
	return ret2, nil
}
