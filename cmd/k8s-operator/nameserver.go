// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// tailscale-operator provides a way to expose services running in a Kubernetes
// cluster to your Tailnet and to make Tailscale nodes available to cluster
// workloads
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sync"

	_ "embed"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	xslices "golang.org/x/exp/slices"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/yaml"
	tsoperator "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/tstime"
	"tailscale.com/types/ptr"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/set"
)

const (
	reasonNameserverCreationFailed  = "NameserverCreationFailed"
	reasonMultipleDNSConfigsPresent = "MultipleDNSConfigsPresent"

	reasonNameserverCreated = "NameserverCreated"

	messageNameserverCreationFailed  = "Failed creating nameserver resources: %v"
	messageMultipleDNSConfigsPresent = "Multiple DNSConfig resources found in cluster. Please ensure no more than one is present."
)

// NameserverReconciler knows how to create nameserver resources in cluster in
// response to users applying DNSConfig.
type NameserverReconciler struct {
	client.Client
	logger      *zap.SugaredLogger
	recorder    record.EventRecorder
	clock       tstime.Clock
	tsNamespace string

	mu                 sync.Mutex           // protects following
	managedNameservers set.Slice[types.UID] // one or none
}

var (
	gaugeNameserverResources = clientmetric.NewGauge("k8s_nameserver_resources")
)

func (a *NameserverReconciler) Reconcile(ctx context.Context, req reconcile.Request) (res reconcile.Result, err error) {
	logger := a.logger.With("dnsConfig", req.Name)
	logger.Debugf("starting reconcile")
	defer logger.Debugf("reconcile finished")

	var dnsCfg tsapi.DNSConfig
	err = a.Get(ctx, req.NamespacedName, &dnsCfg)
	if apierrors.IsNotFound(err) {
		// Request object not found, could have been deleted after reconcile request.
		logger.Debugf("dnsconfig not found, assuming it was deleted")
		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to get dnsconfig: %w", err)
	}
	if !dnsCfg.DeletionTimestamp.IsZero() {
		ix := xslices.Index(dnsCfg.Finalizers, FinalizerName)
		if ix < 0 {
			logger.Debugf("no finalizer, nothing to do")
			return reconcile.Result{}, nil
		}
		logger.Info("Cleaning up DNSConfig resources")
		if err := a.maybeCleanup(ctx, &dnsCfg, logger); err != nil {
			logger.Errorf("error cleaning up reconciler resource: %v", err)
			return res, err
		}
		dnsCfg.Finalizers = append(dnsCfg.Finalizers[:ix], dnsCfg.Finalizers[ix+1:]...)
		if err := a.Update(ctx, &dnsCfg); err != nil {
			logger.Errorf("error removing finalizer: %v", err)
			return reconcile.Result{}, err
		}
		logger.Infof("Nameserver resources cleaned up")
		return reconcile.Result{}, nil
	}

	oldCnStatus := dnsCfg.Status.DeepCopy()
	setStatus := func(dnsCfg *tsapi.DNSConfig, conditionType tsapi.ConnectorConditionType, status metav1.ConditionStatus, reason, message string) (reconcile.Result, error) {
		tsoperator.SetDNSConfigCondition(dnsCfg, tsapi.NameserverReady, status, reason, message, dnsCfg.Generation, a.clock, logger)
		if !apiequality.Semantic.DeepEqual(oldCnStatus, dnsCfg.Status) {
			// An error encountered here should get returned by the Reconcile function.
			if updateErr := a.Client.Status().Update(ctx, dnsCfg); updateErr != nil {
				err = errors.Wrap(err, updateErr.Error())
			}
		}
		return res, err
	}
	var dnsCfgs tsapi.DNSConfigList
	if err := a.List(ctx, &dnsCfgs); err != nil {
		return res, fmt.Errorf("error listing DNSConfigs: %w", err)
	}
	if len(dnsCfgs.Items) > 1 { // enforce DNSConfig to be a singleton
		msg := "invalid cluster configuration: more than one tailscale.com/dnsconfigs found. Please ensure that no more than one is created."
		logger.Error(msg)
		a.recorder.Event(&dnsCfg, corev1.EventTypeWarning, reasonMultipleDNSConfigsPresent, messageMultipleDNSConfigsPresent)
		setStatus(&dnsCfg, tsapi.NameserverReady, metav1.ConditionFalse, reasonMultipleDNSConfigsPresent, messageMultipleDNSConfigsPresent)
	}

	if !slices.Contains(dnsCfg.Finalizers, FinalizerName) {
		logger.Infof("ensuring nameserver resources")
		dnsCfg.Finalizers = append(dnsCfg.Finalizers, FinalizerName)
		if err := a.Update(ctx, &dnsCfg); err != nil {
			msg := fmt.Sprintf(messageNameserverCreationFailed, err)
			logger.Error(msg)
			return setStatus(&dnsCfg, tsapi.NameserverReady, metav1.ConditionFalse, reasonNameserverCreationFailed, msg)
		}
	}
	if err := a.maybeProvision(ctx, &dnsCfg, logger); err != nil {
		return reconcile.Result{}, fmt.Errorf("error provisioning nameserver resources: %w", err)
	}

	a.mu.Lock()
	a.managedNameservers.Add(dnsCfg.UID)
	a.mu.Unlock()
	gaugeNameserverResources.Set(int64(a.managedNameservers.Len()))

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "nameserver", Namespace: a.tsNamespace},
	}
	if err := a.Client.Get(ctx, client.ObjectKeyFromObject(svc), svc); err != nil {
		return res, fmt.Errorf("error getting Service: %w", err)
	}
	if ip := svc.Spec.ClusterIP; ip != "" && ip != "None" {
		dnsCfg.Status.NameserverStatus = &tsapi.NameserverStatus{
			IP: ip,
		}
		return setStatus(&dnsCfg, tsapi.NameserverReady, metav1.ConditionTrue, reasonNameserverCreated, reasonNameserverCreated)
	}
	logger.Info("nameserver Service does not have an IP address allocated, waiting...")
	return reconcile.Result{}, nil
}

type deployCfg struct {
	imageRepo string
	imageTag  string
}

func (a *NameserverReconciler) maybeProvision(ctx context.Context, dnsCfg *tsapi.DNSConfig, logger *zap.SugaredLogger) error {
	crl := childResourceLabels(dnsCfg.Name, a.tsNamespace, "nameserver")
	cfg := deployCfg{
		imageRepo: "tailscale/k8s-nameserver",
		imageTag:  "unstable",
	}
	if dnsCfg.Spec.Nameserver.Image.Repo != "" {
		cfg.imageRepo = dnsCfg.Spec.Nameserver.Image.Repo
	}
	if dnsCfg.Spec.Nameserver.Image.Tag != "" {
		cfg.imageTag = dnsCfg.Spec.Nameserver.Image.Tag
	}
	for _, deployable := range []deployable{cmDeployable, saDeployable, svcDeployable, deployDeployable} {
		obj := deployable.objTemplate()
		if err := yaml.Unmarshal(deployable.yaml, obj); err != nil {
			return fmt.Errorf("error unmarshalling yaml: %w", err)
		}
		obj.SetLabels(crl)
		obj.SetNamespace(a.tsNamespace)
		obj.SetOwnerReferences([]metav1.OwnerReference{*metav1.NewControllerRef(dnsCfg, tsapi.SchemeGroupVersion.WithKind("DNSConfig"))})
		obj, err := deployable.updateObj(obj, cfg)
		if err != nil {
			return fmt.Errorf("error updating object of kind: %s", obj.GetObjectKind().GroupVersionKind().Kind)
		}
		bs, err := json.Marshal(obj)
		if err != nil {
			return fmt.Errorf("error marshalling object: %s", obj.GetObjectKind().GroupVersionKind().Kind)
		}
		// We use Server-Side Apply here to ensure that we don't
		// overwrite dnsconfig ConfigMap contents, set by
		// dns-reconciler. SSA usage here is not a generically correct
		// way how to do SSA. Because the objects are unmarshalled from
		// yaml, we'd always end up owning all required fields. However,
		// for our use case this is fine as here we are creating the
		// objects anew, so we know that we want to own the required
		// fields.
		patch := client.RawPatch(types.ApplyPatchType, bs)
		if err := a.Client.Patch(ctx, obj, patch, &client.PatchOptions{
			Force:        ptr.To(true), // controllers should always force fields they want to own
			FieldManager: "nameserver-reconciler",
		}); err != nil {
			return fmt.Errorf("error patching resource: %w", err)
		}
	}
	return nil
}

// maybeCleanup removes DNSConfig from being tracked. The cluster resources
// created, will be automatically garbage collected as they are owned by the
// DNSConfig.
func (a *NameserverReconciler) maybeCleanup(ctx context.Context, dnsCfg *tsapi.DNSConfig, logger *zap.SugaredLogger) error {
	a.mu.Lock()
	a.managedNameservers.Remove(dnsCfg.UID)
	a.mu.Unlock()
	gaugeNameserverResources.Set(int64(a.managedNameservers.Len()))
	return nil
}

type deployable struct {
	yaml        []byte
	objTemplate func() client.Object
	updateObj   func(client.Object, deployCfg) (client.Object, error)
}

var (
	//go:embed deploy/manifests/nameserver/cm.yaml
	cmYaml []byte
	//go:embed deploy/manifests/nameserver/deploy.yaml
	deployYaml []byte
	//go:embed deploy/manifests/nameserver/sa.yaml
	saYaml []byte
	//go:embed deploy/manifests/nameserver/svc.yaml
	svcYaml []byte

	cmDeployable = deployable{
		yaml: cmYaml,
		objTemplate: func() client.Object {
			return &corev1.ConfigMap{TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}}
		},
		updateObj: func(obj client.Object, _ deployCfg) (client.Object, error) { return obj, nil },
	}
	deployDeployable = deployable{
		yaml: deployYaml,
		objTemplate: func() client.Object {
			return &appsv1.Deployment{TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: appsv1.SchemeGroupVersion.Identifier()}}
		},
		updateObj: func(obj client.Object, cfg deployCfg) (client.Object, error) {
			deploy, ok := obj.(*appsv1.Deployment)
			if !ok {
				return nil, errors.New("failed to convert obj to Deployment")
			}
			deploy.Spec.Template.Spec.Containers[0].Image = fmt.Sprintf("%s:%s", cfg.imageRepo, cfg.imageTag)
			return deploy, nil
		},
	}
	saDeployable = deployable{
		yaml:      saYaml,
		updateObj: func(obj client.Object, _ deployCfg) (client.Object, error) { return obj, nil },
		objTemplate: func() client.Object {
			return &corev1.ServiceAccount{TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}}
		},
	}
	svcDeployable = deployable{
		yaml:      svcYaml,
		updateObj: func(obj client.Object, _ deployCfg) (client.Object, error) { return obj, nil },
		objTemplate: func() client.Object {
			return &corev1.Service{TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}}
		},
	}
)
