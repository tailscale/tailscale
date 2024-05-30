// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"fmt"
	"log"
	"slices"
	"sync"

	_ "embed"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	xslices "golang.org/x/exp/slices"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/yaml"
	"tailscale.com/client/tailscale"
	tsoperator "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/tstime"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/mak"
	"tailscale.com/util/set"
)

const (
	reasonNameserverCreationFailed  = "NameserverCreationFailed"
	reasonMultipleDNSConfigsPresent = "MultipleDNSConfigsPresent"

	reasonNameserverCreated = "NameserverCreated"

	messageNameserverCreationFailed  = "Failed creating nameserver resources: %v"
	messageMultipleDNSConfigsPresent = "Multiple DNSConfig resources found in cluster. Please ensure no more than one is present."

	defaultNameserverImageRepo = "tailscale/k8s-nameserver"
	// TODO (irbekrm): once we start publishing nameserver images for stable
	// track, replace 'unstable' here with the version of this operator
	// instance.
	defaultNameserverImageTag = "unstable"
)

// NameserverReconciler knows how to create nameserver resources in cluster in
// response to users applying DNSConfig.
type NameserverReconciler struct {
	client.Client
	tsClient    tsClient
	logger      *zap.SugaredLogger
	recorder    record.EventRecorder
	clock       tstime.Clock
	tsNamespace string
	defaultTags []string

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
		dnsCfg.Status.Nameserver = &tsapi.NameserverStatus{
			IP: ip,
		}
		return setStatus(&dnsCfg, tsapi.NameserverReady, metav1.ConditionTrue, reasonNameserverCreated, reasonNameserverCreated)
	}
	logger.Info("nameserver Service does not have an IP address allocated, waiting...")
	return reconcile.Result{}, nil
}

func nameserverResourceLabels(name, namespace string) map[string]string {
	labels := childResourceLabels(name, namespace, "nameserver")
	labels["app.kubernetes.io/name"] = "tailscale"
	labels["app.kubernetes.io/component"] = "nameserver"
	return labels
}

func (a *NameserverReconciler) maybeProvision(ctx context.Context, tsDNSCfg *tsapi.DNSConfig, logger *zap.SugaredLogger) error {
	labels := nameserverResourceLabels(tsDNSCfg.Name, a.tsNamespace)
	dCfg := &deployConfig{
		ownerRefs: []metav1.OwnerReference{*metav1.NewControllerRef(tsDNSCfg, tsapi.SchemeGroupVersion.WithKind("DNSConfig"))},
		namespace: a.tsNamespace,
		labels:    labels,
		imageRepo: defaultNameserverImageRepo,
		imageTag:  defaultNameserverImageTag,
		tsClient:  a.tsClient,
		tags:      a.defaultTags,
	}
	if tsDNSCfg.Spec.Nameserver.Image != nil && tsDNSCfg.Spec.Nameserver.Image.Repo != "" {
		dCfg.imageRepo = tsDNSCfg.Spec.Nameserver.Image.Repo
	}
	if tsDNSCfg.Spec.Nameserver.Image != nil && tsDNSCfg.Spec.Nameserver.Image.Tag != "" {
		dCfg.imageTag = tsDNSCfg.Spec.Nameserver.Image.Tag
	}
	for _, deployable := range []deployable{saDeployable, deployDeployable, svcDeployable, cmDeployable, secretDeployable, roleDeployable, roleBindingDeployable} {
		if err := deployable.updateObj(ctx, dCfg, a.Client); err != nil {
			return fmt.Errorf("error reconciling %s: %w", deployable.kind, err)
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

func newAuthKey(ctx context.Context, tsClient tsClient, tags []string) (string, error) {
	caps := tailscale.KeyCapabilities{
		Devices: tailscale.KeyDeviceCapabilities{
			Create: tailscale.KeyDeviceCreateCapabilities{
				Reusable:      false,
				Preauthorized: true,
				Tags:          tags,
			},
		},
	}
	key, _, err := tsClient.CreateKey(ctx, caps)
	if err != nil {
		return "", err
	}
	return key, nil
}

type deployable struct {
	kind      string
	updateObj func(context.Context, *deployConfig, client.Client) error
}

type deployConfig struct {
	imageRepo string
	imageTag  string
	labels    map[string]string
	ownerRefs []metav1.OwnerReference
	namespace string
	tsClient  tsClient
	tags      []string
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
	//go:embed deploy/manifests/nameserver/secret.yaml
	secretYaml []byte
	//go:embed deploy/manifests/nameserver/role.yaml
	roleYaml []byte
	//go:embed deploy/manifests/nameserver/rolebinding.yaml
	rolebindingYaml []byte

	deployDeployable = deployable{
		kind: "Deployment",
		updateObj: func(ctx context.Context, cfg *deployConfig, kubeClient client.Client) error {
			d := new(appsv1.Deployment)
			if err := yaml.Unmarshal(deployYaml, &d); err != nil {
				return fmt.Errorf("error unmarshalling Deployment yaml: %w", err)
			}
			d.Spec.Template.Spec.Containers[0].Image = fmt.Sprintf("%s:%s", cfg.imageRepo, cfg.imageTag)
			d.ObjectMeta.Namespace = cfg.namespace
			d.ObjectMeta.Labels = cfg.labels
			d.ObjectMeta.OwnerReferences = cfg.ownerRefs
			updateF := func(oldD *appsv1.Deployment) {
				oldD.Spec = d.Spec
			}
			// Get all proxy ConfigMaps and mount them
			cmList := &corev1.ConfigMapList{}
			sel, err := metav1.LabelSelectorAsSelector(&metav1.LabelSelector{MatchLabels: map[string]string{"component": "proxies"}})
			if err != nil {
				return fmt.Errorf("error creating label selector: %w", err)
			}
			if err := kubeClient.List(ctx, cmList, &client.ListOptions{LabelSelector: sel}); err != nil {
				return fmt.Errorf("error listing ConfigMaps: %w", err)
			}
			for _, cm := range cmList.Items {
				volume := corev1.Volume{
					Name: cm.Name,
					VolumeSource: corev1.VolumeSource{
						ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{Name: cm.Name},
						},
					},
				}
				volumeMount := corev1.VolumeMount{
					Name:      cm.Name,
					MountPath: fmt.Sprintf("/services/%s", cm.Name),
					ReadOnly:  true,
				}
				d.Spec.Template.Spec.Volumes = append(d.Spec.Template.Spec.Volumes, volume)
				d.Spec.Template.Spec.Containers[0].VolumeMounts = append(d.Spec.Template.Spec.Containers[0].VolumeMounts, volumeMount)
			}
			_, err = createOrUpdate[appsv1.Deployment](ctx, kubeClient, cfg.namespace, d, updateF)
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
			_, err := createOrUpdate[corev1.Service](ctx, kubeClient, cfg.namespace, svc, func(*corev1.Service) {})
			return err
		},
	}
	secretDeployable = deployable{
		kind: "Secret",
		updateObj: func(ctx context.Context, cfg *deployConfig, kubeClient client.Client) error {
			secret := new(corev1.Secret)
			if err := yaml.Unmarshal(secretYaml, &secret); err != nil {
				return fmt.Errorf("error unmarshalling Secret yaml: %w", err)
			}
			// TODO: make the nameserver tsnet Server actually store state in kube secret
			secret.ObjectMeta.Labels = cfg.labels
			secret.ObjectMeta.OwnerReferences = cfg.ownerRefs
			secret.ObjectMeta.Namespace = cfg.namespace
			// Get the secret
			oldS := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "nameserver-key", Namespace: cfg.namespace},
			}
			if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(oldS), oldS); apierrors.IsNotFound(err) {
				key, err := newAuthKey(ctx, cfg.tsClient, cfg.tags)
				if err != nil {
					return fmt.Errorf("error creating new auth key: %w", err)
				}
				// write it to the Secret
				mak.Set(&secret.StringData, "ts_auth_key", key)
				return kubeClient.Create(ctx, secret)
			} else if err != nil {
				return fmt.Errorf("error looking up 'dnsrecords' Secret: %w", err)
			} else {
				log.Printf("'nameserver-key' Secret exists, do nothing")
				return nil
			}
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
	roleDeployable = deployable{
		kind: "Role",
		updateObj: func(ctx context.Context, cfg *deployConfig, kubeClient client.Client) error {
			role := new(rbacv1.Role)
			if err := yaml.Unmarshal(roleYaml, &role); err != nil {
				return fmt.Errorf("error unmarshalling Role yaml: %w", err)
			}
			role.ObjectMeta.Labels = cfg.labels
			role.ObjectMeta.OwnerReferences = cfg.ownerRefs
			role.ObjectMeta.Namespace = cfg.namespace
			_, err := createOrUpdate[rbacv1.Role](ctx, kubeClient, cfg.namespace, role, func(*rbacv1.Role) {})
			return err
		},
	}
	roleBindingDeployable = deployable{
		kind: "RoleBinding",
		updateObj: func(ctx context.Context, cfg *deployConfig, kubeClient client.Client) error {
			rb := new(rbacv1.RoleBinding)
			if err := yaml.Unmarshal(rolebindingYaml, &rb); err != nil {
				return fmt.Errorf("error unmarshalling RoleBinding yaml: %w", err)
			}
			rb.ObjectMeta.Labels = cfg.labels
			rb.ObjectMeta.OwnerReferences = cfg.ownerRefs
			rb.ObjectMeta.Namespace = cfg.namespace
			_, err := createOrUpdate[rbacv1.RoleBinding](ctx, kubeClient, cfg.namespace, rb, func(*rbacv1.RoleBinding) {})
			return err
		},
	}
)
