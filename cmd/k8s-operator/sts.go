// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"

	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apiserver/pkg/storage/names"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"
	"tailscale.com/client/tailscale"
	"tailscale.com/ipn"
	tsoperator "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/net/netutil"
	"tailscale.com/tailcfg"
	"tailscale.com/types/opt"
	"tailscale.com/types/ptr"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/mak"
)

const (
	// Labels that the operator sets on StatefulSets and Pods. If you add a
	// new label here, do also add it to tailscaleManagedLabels var to
	// ensure that it does not get overwritten by ProxyClass configuration.
	LabelManaged         = "tailscale.com/managed"
	LabelParentType      = "tailscale.com/parent-resource-type"
	LabelParentName      = "tailscale.com/parent-resource"
	LabelParentNamespace = "tailscale.com/parent-resource-ns"

	// LabelProxyClass can be set by users on Connectors, tailscale
	// Ingresses and Services that define cluster ingress or cluster egress,
	// to specify that configuration in this ProxyClass should be applied to
	// resources created for the Connector, Ingress or Service.
	LabelProxyClass = "tailscale.com/proxy-class"

	FinalizerName = "tailscale.com/finalizer"

	// Annotations settable by users on services.
	AnnotationExpose             = "tailscale.com/expose"
	AnnotationTags               = "tailscale.com/tags"
	AnnotationHostname           = "tailscale.com/hostname"
	annotationTailnetTargetIPOld = "tailscale.com/ts-tailnet-target-ip"
	AnnotationTailnetTargetIP    = "tailscale.com/tailnet-ip"
	//MagicDNS name of tailnet node.
	AnnotationTailnetTargetFQDN = "tailscale.com/tailnet-fqdn"

	// Annotations settable by users on ingresses.
	AnnotationFunnel = "tailscale.com/funnel"

	// If set to true, set up iptables/nftables rules in the proxy forward
	// cluster traffic to the tailnet IP of that proxy. This can only be set
	// on an Ingress. This is useful in cases where a cluster target needs
	// to be able to reach a cluster workload exposed to tailnet via Ingress
	// using the same hostname as a tailnet workload (in this case, the
	// MagicDNS name of the ingress proxy). This annotation is experimental.
	// If it is set to true, the proxy set up for Ingress, will run
	// tailscale in non-userspace, with NET_ADMIN cap for tailscale
	// container and will also run a privileged init container that enables
	// forwarding.
	// Eventually this behaviour might become the default.
	AnnotationExperimentalForwardClusterTrafficViaL7IngresProxy = "tailscale.com/experimental-forward-cluster-traffic-via-ingress"

	// Annotations set by the operator on pods to trigger restarts when the
	// hostname, IP, FQDN or tailscaled config changes. If you add a new
	// annotation here, also add it to tailscaleManagedAnnotations var to
	// ensure that it does not get removed when a ProxyClass configuration
	// is applied.
	podAnnotationLastSetClusterIP         = "tailscale.com/operator-last-set-cluster-ip"
	podAnnotationLastSetTailnetTargetIP   = "tailscale.com/operator-last-set-ts-tailnet-target-ip"
	podAnnotationLastSetTailnetTargetFQDN = "tailscale.com/operator-last-set-ts-tailnet-target-fqdn"
	// podAnnotationLastSetConfigFileHash is sha256 hash of the current tailscaled configuration contents.
	podAnnotationLastSetConfigFileHash = "tailscale.com/operator-last-set-config-file-hash"

	// tailscaledConfigKey is the name of the key in proxy Secret Data that
	// holds the tailscaled config contents.
	tailscaledConfigKey = "tailscaled"
)

var (
	// tailscaleManagedLabels are label keys that tailscale operator sets on StatefulSets and Pods.
	tailscaleManagedLabels = []string{LabelManaged, LabelParentType, LabelParentName, LabelParentNamespace, "app"}
	// tailscaleManagedAnnotations are annotation keys that tailscale operator sets on StatefulSets and Pods.
	tailscaleManagedAnnotations = []string{podAnnotationLastSetClusterIP, podAnnotationLastSetTailnetTargetIP, podAnnotationLastSetTailnetTargetFQDN, podAnnotationLastSetConfigFileHash}
)

type tailscaleSTSConfig struct {
	ParentResourceName  string
	ParentResourceUID   string
	ChildResourceLabels map[string]string

	ServeConfig     *ipn.ServeConfig // if serve config is set, this is a proxy for Ingress
	ClusterTargetIP string           // ingress target
	// If set to true, operator should configure containerboot to forward
	// cluster traffic via the proxy set up for Kubernetes Ingress.
	ForwardClusterTrafficViaL7IngressProxy bool

	TailnetTargetIP string // egress target IP

	TailnetTargetFQDN string // egress target FQDN

	Hostname string
	Tags     []string // if empty, use defaultTags

	// Connector specifies a configuration of a Connector instance if that's
	// what this StatefulSet should be created for.
	Connector *connector

	ProxyClass string
}

type connector struct {
	// routes is a list of subnet routes that this Connector should expose.
	routes string
	// isExitNode defines whether this Connector should act as an exit node.
	isExitNode bool
}
type tsnetServer interface {
	CertDomains() []string
}

type tailscaleSTSReconciler struct {
	client.Client
	tsnetServer            tsnetServer
	tsClient               tsClient
	defaultTags            []string
	operatorNamespace      string
	proxyImage             string
	proxyPriorityClassName string
	tsFirewallMode         string
}

func (sts tailscaleSTSReconciler) validate() error {
	if sts.tsFirewallMode != "" && !isValidFirewallMode(sts.tsFirewallMode) {
		return fmt.Errorf("invalid proxy firewall mode %s, valid modes are iptables, nftables or unset", sts.tsFirewallMode)
	}
	return nil
}

// IsHTTPSEnabledOnTailnet reports whether HTTPS is enabled on the tailnet.
func (a *tailscaleSTSReconciler) IsHTTPSEnabledOnTailnet() bool {
	return len(a.tsnetServer.CertDomains()) > 0
}

// Provision ensures that the StatefulSet for the given service is running and
// up to date.
func (a *tailscaleSTSReconciler) Provision(ctx context.Context, logger *zap.SugaredLogger, sts *tailscaleSTSConfig) (*corev1.Service, error) {
	// Do full reconcile.
	// TODO (don't create Service for the Connector)
	hsvc, err := a.reconcileHeadlessService(ctx, logger, sts)
	if err != nil {
		return nil, fmt.Errorf("failed to reconcile headless service: %w", err)
	}

	secretName, tsConfigHash, err := a.createOrGetSecret(ctx, logger, sts, hsvc)
	if err != nil {
		return nil, fmt.Errorf("failed to create or get API key secret: %w", err)
	}
	_, err = a.reconcileSTS(ctx, logger, sts, hsvc, secretName, tsConfigHash)
	if err != nil {
		return nil, fmt.Errorf("failed to reconcile statefulset: %w", err)
	}

	return hsvc, nil
}

// Cleanup removes all resources associated that were created by Provision with
// the given labels. It returns true when all resources have been removed,
// otherwise it returns false and the caller should retry later.
func (a *tailscaleSTSReconciler) Cleanup(ctx context.Context, logger *zap.SugaredLogger, labels map[string]string) (done bool, _ error) {
	// Need to delete the StatefulSet first, and delete it with foreground
	// cascading deletion. That way, the pod that's writing to the Secret will
	// stop running before we start looking at the Secret's contents, and
	// assuming k8s ordering semantics don't mess with us, that should avoid
	// tailscale device deletion races where we fail to notice a device that
	// should be removed.
	sts, err := getSingleObject[appsv1.StatefulSet](ctx, a.Client, a.operatorNamespace, labels)
	if err != nil {
		return false, fmt.Errorf("getting statefulset: %w", err)
	}
	if sts != nil {
		if !sts.GetDeletionTimestamp().IsZero() {
			// Deletion in progress, check again later. We'll get another
			// notification when the deletion is complete.
			logger.Debugf("waiting for statefulset %s/%s deletion", sts.GetNamespace(), sts.GetName())
			return false, nil
		}
		err := a.DeleteAllOf(ctx, &appsv1.StatefulSet{}, client.InNamespace(a.operatorNamespace), client.MatchingLabels(labels), client.PropagationPolicy(metav1.DeletePropagationForeground))
		if err != nil {
			return false, fmt.Errorf("deleting statefulset: %w", err)
		}
		logger.Debugf("started deletion of statefulset %s/%s", sts.GetNamespace(), sts.GetName())
		return false, nil
	}

	id, _, _, err := a.DeviceInfo(ctx, labels)
	if err != nil {
		return false, fmt.Errorf("getting device info: %w", err)
	}
	if id != "" {
		logger.Debugf("deleting device %s from control", string(id))
		if err := a.tsClient.DeleteDevice(ctx, string(id)); err != nil {
			errResp := &tailscale.ErrResponse{}
			if ok := errors.As(err, errResp); ok && errResp.Status == http.StatusNotFound {
				logger.Debugf("device %s not found, likely because it has already been deleted from control", string(id))
			} else {
				return false, fmt.Errorf("deleting device: %w", err)
			}
		} else {
			logger.Debugf("device %s deleted from control", string(id))
		}
	}

	types := []client.Object{
		&corev1.Service{},
		&corev1.Secret{},
	}
	for _, typ := range types {
		if err := a.DeleteAllOf(ctx, typ, client.InNamespace(a.operatorNamespace), client.MatchingLabels(labels)); err != nil {
			return false, err
		}
	}
	return true, nil
}

// maxStatefulSetNameLength is maximum length the StatefulSet name can
// have to NOT result in a too long value for controller-revision-hash
// label value (see https://github.com/kubernetes/kubernetes/issues/64023).
// controller-revision-hash label value consists of StatefulSet's name + hyphen + revision hash.
// Maximum label value length is 63 chars. Length of revision hash is 10 chars.
// https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#syntax-and-character-set
// https://github.com/kubernetes/kubernetes/blob/v1.28.4/pkg/controller/history/controller_history.go#L90-L104
const maxStatefulSetNameLength = 63 - 10 - 1

// statefulSetNameBase accepts name of parent resource and returns a string in
// form ts-<portion-of-parentname>- that, when passed to Kubernetes name
// generation will NOT result in a StatefulSet name longer than 52 chars.
// This is done because of https://github.com/kubernetes/kubernetes/issues/64023.
func statefulSetNameBase(parent string) string {
	base := fmt.Sprintf("ts-%s-", parent)
	generator := names.SimpleNameGenerator
	for {
		generatedName := generator.GenerateName(base)
		excess := len(generatedName) - maxStatefulSetNameLength
		if excess <= 0 {
			return base
		}
		base = base[:len(base)-1-excess] // cut off the excess chars
		base = base + "-"                // re-instate the dash
	}
}

func (a *tailscaleSTSReconciler) reconcileHeadlessService(ctx context.Context, logger *zap.SugaredLogger, sts *tailscaleSTSConfig) (*corev1.Service, error) {
	nameBase := statefulSetNameBase(sts.ParentResourceName)
	hsvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: nameBase,
			Namespace:    a.operatorNamespace,
			Labels:       sts.ChildResourceLabels,
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "None",
			Selector: map[string]string{
				"app": sts.ParentResourceUID,
			},
		},
	}
	logger.Debugf("reconciling headless service for StatefulSet")
	return createOrUpdate(ctx, a.Client, a.operatorNamespace, hsvc, func(svc *corev1.Service) { svc.Spec = hsvc.Spec })
}

func (a *tailscaleSTSReconciler) createOrGetSecret(ctx context.Context, logger *zap.SugaredLogger, stsC *tailscaleSTSConfig, hsvc *corev1.Service) (string, string, error) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			// Hardcode a -0 suffix so that in future, if we support
			// multiple StatefulSet replicas, we can provision -N for
			// those.
			Name:      hsvc.Name + "-0",
			Namespace: a.operatorNamespace,
			Labels:    stsC.ChildResourceLabels,
		},
	}
	var orig *corev1.Secret // unmodified copy of secret
	if err := a.Get(ctx, client.ObjectKeyFromObject(secret), secret); err == nil {
		logger.Debugf("secret %s/%s already exists", secret.GetNamespace(), secret.GetName())
		orig = secret.DeepCopy()
	} else if !apierrors.IsNotFound(err) {
		return "", "", err
	}

	var (
		authKey, hash string
	)
	if orig == nil {
		// Initially it contains only tailscaled config, but when the
		// proxy starts, it will also store there the state, certs and
		// ACME account key.
		sts, err := getSingleObject[appsv1.StatefulSet](ctx, a.Client, a.operatorNamespace, stsC.ChildResourceLabels)
		if err != nil {
			return "", "", err
		}
		if sts != nil {
			// StatefulSet exists, so we have already created the secret.
			// If the secret is missing, they should delete the StatefulSet.
			logger.Errorf("Tailscale proxy secret doesn't exist, but the corresponding StatefulSet %s/%s already does. Something is wrong, please delete the StatefulSet.", sts.GetNamespace(), sts.GetName())
			return "", "", nil
		}
		// Create API Key secret which is going to be used by the statefulset
		// to authenticate with Tailscale.
		logger.Debugf("creating authkey for new tailscale proxy")
		tags := stsC.Tags
		if len(tags) == 0 {
			tags = a.defaultTags
		}
		authKey, err = a.newAuthKey(ctx, tags)
		if err != nil {
			return "", "", err
		}
	}
	confFileBytes, h, err := tailscaledConfig(stsC, authKey, orig)
	if err != nil {
		return "", "", fmt.Errorf("error creating tailscaled config: %w", err)
	}
	hash = h
	mak.Set(&secret.StringData, tailscaledConfigKey, string(confFileBytes))

	if stsC.ServeConfig != nil {
		j, err := json.Marshal(stsC.ServeConfig)
		if err != nil {
			return "", "", err
		}
		mak.Set(&secret.StringData, "serve-config", string(j))
	}

	if orig != nil {
		logger.Debugf("patching the existing proxy Secret with tailscaled config %s", sanitizeConfigBytes(secret.Data[tailscaledConfigKey]))
		if err := a.Patch(ctx, secret, client.MergeFrom(orig)); err != nil {
			return "", "", err
		}
	} else {
		logger.Debugf("creating a new Secret for the proxy with tailscaled config %s", sanitizeConfigBytes([]byte(secret.StringData[tailscaledConfigKey])))
		if err := a.Create(ctx, secret); err != nil {
			return "", "", err
		}
	}
	return secret.Name, hash, nil
}

// sanitizeConfigBytes returns ipn.ConfigVAlpha in string form with redacted
// auth key.
func sanitizeConfigBytes(bs []byte) string {
	c := &ipn.ConfigVAlpha{}
	if err := json.Unmarshal(bs, c); err != nil {
		return "invalid config"
	}
	if c.AuthKey != nil {
		c.AuthKey = ptr.To("**redacted**")
	}
	sanitizedBytes, err := json.Marshal(c)
	if err != nil {
		return "invalid config"
	}
	return string(sanitizedBytes)
}

// DeviceInfo returns the device ID and hostname for the Tailscale device
// associated with the given labels.
func (a *tailscaleSTSReconciler) DeviceInfo(ctx context.Context, childLabels map[string]string) (id tailcfg.StableNodeID, hostname string, ips []string, err error) {
	sec, err := getSingleObject[corev1.Secret](ctx, a.Client, a.operatorNamespace, childLabels)
	if err != nil {
		return "", "", nil, err
	}
	if sec == nil {
		return "", "", nil, nil
	}
	id = tailcfg.StableNodeID(sec.Data["device_id"])
	if id == "" {
		return "", "", nil, nil
	}
	// Kubernetes chokes on well-formed FQDNs with the trailing dot, so we have
	// to remove it.
	hostname = strings.TrimSuffix(string(sec.Data["device_fqdn"]), ".")
	if hostname == "" {
		return "", "", nil, nil
	}
	if rawDeviceIPs, ok := sec.Data["device_ips"]; ok {
		if err := json.Unmarshal(rawDeviceIPs, &ips); err != nil {
			return "", "", nil, err
		}
	}
	return id, hostname, ips, nil
}

func (a *tailscaleSTSReconciler) newAuthKey(ctx context.Context, tags []string) (string, error) {
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

//go:embed deploy/manifests/proxy.yaml
var proxyYaml []byte

//go:embed deploy/manifests/userspace-proxy.yaml
var userspaceProxyYaml []byte

func (a *tailscaleSTSReconciler) reconcileSTS(ctx context.Context, logger *zap.SugaredLogger, sts *tailscaleSTSConfig, headlessSvc *corev1.Service, proxySecret, tsConfigHash string) (*appsv1.StatefulSet, error) {
	ss := new(appsv1.StatefulSet)
	if sts.ServeConfig != nil && sts.ForwardClusterTrafficViaL7IngressProxy != true { // If forwarding cluster traffic via is required we need non-userspace + NET_ADMIN + forwarding
		if err := yaml.Unmarshal(userspaceProxyYaml, &ss); err != nil {
			return nil, fmt.Errorf("failed to unmarshal userspace proxy spec: %v", err)
		}
	} else {
		if err := yaml.Unmarshal(proxyYaml, &ss); err != nil {
			return nil, fmt.Errorf("failed to unmarshal proxy spec: %w", err)
		}
		for i := range ss.Spec.Template.Spec.InitContainers {
			c := &ss.Spec.Template.Spec.InitContainers[i]
			if c.Name == "sysctler" {
				c.Image = a.proxyImage
				break
			}
		}
	}
	pod := &ss.Spec.Template
	container := &pod.Spec.Containers[0]
	proxyClass := new(tsapi.ProxyClass)
	if sts.ProxyClass != "" {
		if err := a.Get(ctx, types.NamespacedName{Name: sts.ProxyClass}, proxyClass); err != nil {
			return nil, fmt.Errorf("failed to get ProxyClass: %w", err)
		}
		if !tsoperator.ProxyClassIsReady(proxyClass) {
			logger.Infof("ProxyClass %s specified for the proxy, but it is not (yet) in a ready state, waiting..")
			return nil, nil
		}
	}
	container.Image = a.proxyImage
	ss.ObjectMeta = metav1.ObjectMeta{
		Name:      headlessSvc.Name,
		Namespace: a.operatorNamespace,
	}
	for key, val := range sts.ChildResourceLabels {
		mak.Set(&ss.ObjectMeta.Labels, key, val)
	}
	ss.Spec.ServiceName = headlessSvc.Name
	ss.Spec.Selector = &metav1.LabelSelector{
		MatchLabels: map[string]string{
			"app": sts.ParentResourceUID,
		},
	}
	mak.Set(&pod.Labels, "app", sts.ParentResourceUID)
	for key, val := range sts.ChildResourceLabels {
		pod.Labels[key] = val // sync StatefulSet labels to Pod to make it easier for users to select the Pod
	}

	// Generic containerboot configuration options.
	container.Env = append(container.Env,
		corev1.EnvVar{
			Name:  "TS_KUBE_SECRET",
			Value: proxySecret,
		},
		corev1.EnvVar{
			Name:  "EXPERIMENTAL_TS_CONFIGFILE_PATH",
			Value: "/etc/tsconfig/tailscaled",
		},
	)
	if sts.ForwardClusterTrafficViaL7IngressProxy {
		container.Env = append(container.Env, corev1.EnvVar{
			Name:  "EXPERIMENTAL_ALLOW_PROXYING_CLUSTER_TRAFFIC_VIA_INGRESS",
			Value: "true",
		})
	}
	// Configure containeboot to run tailscaled with a configfile read from the state Secret.
	mak.Set(&ss.Spec.Template.Annotations, podAnnotationLastSetConfigFileHash, tsConfigHash)
	pod.Spec.Volumes = append(ss.Spec.Template.Spec.Volumes, corev1.Volume{
		Name: "tailscaledconfig",
		VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName: proxySecret,
				Items: []corev1.KeyToPath{{
					Key:  tailscaledConfigKey,
					Path: tailscaledConfigKey,
				}},
			},
		},
	})
	container.VolumeMounts = append(container.VolumeMounts, corev1.VolumeMount{
		Name:      "tailscaledconfig",
		ReadOnly:  true,
		MountPath: "/etc/tsconfig",
	})

	if a.tsFirewallMode != "" {
		container.Env = append(container.Env, corev1.EnvVar{
			Name:  "TS_DEBUG_FIREWALL_MODE",
			Value: a.tsFirewallMode,
		})
	}
	pod.Spec.PriorityClassName = a.proxyPriorityClassName

	// Ingress/egress proxy configuration options.
	if sts.ClusterTargetIP != "" {
		container.Env = append(container.Env, corev1.EnvVar{
			Name:  "TS_DEST_IP",
			Value: sts.ClusterTargetIP,
		})
		mak.Set(&ss.Spec.Template.Annotations, podAnnotationLastSetClusterIP, sts.ClusterTargetIP)
	} else if sts.TailnetTargetIP != "" {
		container.Env = append(container.Env, corev1.EnvVar{
			Name:  "TS_TAILNET_TARGET_IP",
			Value: sts.TailnetTargetIP,
		})
		mak.Set(&ss.Spec.Template.Annotations, podAnnotationLastSetTailnetTargetIP, sts.TailnetTargetIP)
	} else if sts.TailnetTargetFQDN != "" {
		container.Env = append(container.Env, corev1.EnvVar{
			Name:  "TS_TAILNET_TARGET_FQDN",
			Value: sts.TailnetTargetFQDN,
		})
		mak.Set(&ss.Spec.Template.Annotations, podAnnotationLastSetTailnetTargetFQDN, sts.TailnetTargetFQDN)
	} else if sts.ServeConfig != nil {
		container.Env = append(container.Env, corev1.EnvVar{
			Name:  "TS_SERVE_CONFIG",
			Value: "/etc/tailscaled/serve-config",
		})
		container.VolumeMounts = append(container.VolumeMounts, corev1.VolumeMount{
			Name:      "serve-config",
			ReadOnly:  true,
			MountPath: "/etc/tailscaled",
		})
		pod.Spec.Volumes = append(ss.Spec.Template.Spec.Volumes, corev1.Volume{
			Name: "serve-config",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: proxySecret,
					Items: []corev1.KeyToPath{{
						Key:  "serve-config",
						Path: "serve-config",
					}},
				},
			},
		})
	}
	logger.Debugf("reconciling statefulset %s/%s", ss.GetNamespace(), ss.GetName())
	if sts.ProxyClass != "" {
		logger.Debugf("configuring proxy resources with ProxyClass %s", sts.ProxyClass)
		ss = applyProxyClassToStatefulSet(proxyClass, ss)
	}
	updateSS := func(s *appsv1.StatefulSet) {
		s.Spec = ss.Spec
		s.ObjectMeta.Labels = ss.Labels
		s.ObjectMeta.Annotations = ss.Annotations
	}
	return createOrUpdate(ctx, a.Client, a.operatorNamespace, ss, updateSS)
}

// mergeStatefulSetLabelsOrAnnots returns a map that contains all keys/values
// present in 'custom' map as well as those keys/values from the current map
// whose keys are present in the 'managed' map. The reason why this merge is
// necessary is to ensure that labels/annotations applied from a ProxyClass get removed
// if they are removed from a ProxyClass or if the ProxyClass no longer applies
// to this StatefulSet whilst any tailscale managed labels/annotations remain present.
func mergeStatefulSetLabelsOrAnnots(current, custom map[string]string, managed []string) map[string]string {
	if custom == nil {
		custom = make(map[string]string)
	}
	if current == nil {
		return custom
	}
	for key, val := range current {
		if slices.Contains(managed, key) {
			custom[key] = val
		}
	}
	return custom
}

func applyProxyClassToStatefulSet(pc *tsapi.ProxyClass, ss *appsv1.StatefulSet) *appsv1.StatefulSet {
	if pc == nil || ss == nil || pc.Spec.StatefulSet == nil {
		return ss
	}

	// Update StatefulSet metadata.
	if wantsSSLabels := pc.Spec.StatefulSet.Labels; len(wantsSSLabels) > 0 {
		ss.ObjectMeta.Labels = mergeStatefulSetLabelsOrAnnots(ss.ObjectMeta.Labels, wantsSSLabels, tailscaleManagedLabels)
	}
	if wantsSSAnnots := pc.Spec.StatefulSet.Annotations; len(wantsSSAnnots) > 0 {
		ss.ObjectMeta.Annotations = mergeStatefulSetLabelsOrAnnots(ss.ObjectMeta.Annotations, wantsSSAnnots, tailscaleManagedAnnotations)
	}

	// Update Pod fields.
	if pc.Spec.StatefulSet.Pod == nil {
		return ss
	}
	wantsPod := pc.Spec.StatefulSet.Pod
	if wantsPodLabels := wantsPod.Labels; len(wantsPodLabels) > 0 {
		ss.Spec.Template.ObjectMeta.Labels = mergeStatefulSetLabelsOrAnnots(ss.Spec.Template.ObjectMeta.Labels, wantsPodLabels, tailscaleManagedLabels)
	}
	if wantsPodAnnots := wantsPod.Annotations; len(wantsPodAnnots) > 0 {
		ss.Spec.Template.ObjectMeta.Annotations = mergeStatefulSetLabelsOrAnnots(ss.Spec.Template.ObjectMeta.Annotations, wantsPodAnnots, tailscaleManagedAnnotations)
	}
	ss.Spec.Template.Spec.SecurityContext = wantsPod.SecurityContext
	ss.Spec.Template.Spec.ImagePullSecrets = wantsPod.ImagePullSecrets
	ss.Spec.Template.Spec.NodeName = wantsPod.NodeName
	ss.Spec.Template.Spec.NodeSelector = wantsPod.NodeSelector
	ss.Spec.Template.Spec.Tolerations = wantsPod.Tolerations

	// Update containers.
	updateContainer := func(overlay *tsapi.Container, base corev1.Container) corev1.Container {
		if overlay == nil {
			return base
		}
		if overlay.SecurityContext != nil {
			base.SecurityContext = overlay.SecurityContext
		}
		base.Resources = overlay.Resources
		return base
	}
	for i, c := range ss.Spec.Template.Spec.Containers {
		if c.Name == "tailscale" {
			ss.Spec.Template.Spec.Containers[i] = updateContainer(wantsPod.TailscaleContainer, ss.Spec.Template.Spec.Containers[i])
			break
		}
	}
	if initContainers := ss.Spec.Template.Spec.InitContainers; len(initContainers) > 0 {
		for i, c := range initContainers {
			if c.Name == "sysctler" {
				ss.Spec.Template.Spec.InitContainers[i] = updateContainer(wantsPod.TailscaleInitContainer, initContainers[i])
				break
			}
		}
	}
	return ss
}

// tailscaledConfig takes a proxy config, a newly generated auth key if
// generated and a Secret with the previous proxy state and auth key and
// produces returns tailscaled configuration and a hash of that configuration.
func tailscaledConfig(stsC *tailscaleSTSConfig, newAuthkey string, oldSecret *corev1.Secret) ([]byte, string, error) {
	conf := ipn.ConfigVAlpha{
		Version:      "alpha0",
		AcceptDNS:    "false",
		AcceptRoutes: "false", // AcceptRoutes defaults to true
		Locked:       "false",
		Hostname:     &stsC.Hostname,
	}
	if stsC.Connector != nil {
		routes, err := netutil.CalcAdvertiseRoutes(stsC.Connector.routes, stsC.Connector.isExitNode)
		if err != nil {
			return nil, "", fmt.Errorf("error calculating routes: %w", err)
		}
		conf.AdvertiseRoutes = routes
	}
	if newAuthkey != "" {
		conf.AuthKey = &newAuthkey
	} else if oldSecret != nil && len(oldSecret.Data[tailscaledConfigKey]) > 0 { // write to StringData, read from Data as StringData is write-only
		origConf := &ipn.ConfigVAlpha{}
		if err := json.Unmarshal([]byte(oldSecret.Data[tailscaledConfigKey]), origConf); err != nil {
			return nil, "", fmt.Errorf("error unmarshaling previous tailscaled config: %w", err)
		}
		conf.AuthKey = origConf.AuthKey
	}
	confFileBytes, err := json.Marshal(conf)
	if err != nil {
		return nil, "", fmt.Errorf("error marshaling tailscaled config : %w", err)
	}
	hash, err := hashBytes(confFileBytes)
	if err != nil {
		return nil, "", fmt.Errorf("error calculating config hash: %w", err)
	}
	return confFileBytes, hash, nil
}

// ptrObject is a type constraint for pointer types that implement
// client.Object.
type ptrObject[T any] interface {
	client.Object
	*T
}

// hashBytes produces a hash for the provided bytes that is the same across
// different invocations of this code. We do not use the
// tailscale.com/deephash.Hash here because that produces a different hash for
// the same value in different tailscale builds. The hash we are producing here
// is used to determine if the container running the Connector Tailscale node
// needs to be restarted. The container does not need restarting when the only
// thing that changed is operator version (the hash is also exposed to users via
// an annotation and might be confusing if it changes without the config having
// changed).
func hashBytes(b []byte) (string, error) {
	h := sha256.New()
	_, err := h.Write(b)
	if err != nil {
		return "", fmt.Errorf("error calculating hash: %w", err)
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// createOrUpdate adds obj to the k8s cluster, unless the object already exists,
// in which case update is called to make changes to it. If update is nil, the
// existing object is returned unmodified.
//
// obj is looked up by its Name and Namespace if Name is set, otherwise it's
// looked up by labels.
func createOrUpdate[T any, O ptrObject[T]](ctx context.Context, c client.Client, ns string, obj O, update func(O)) (O, error) {
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
func getSingleObject[T any, O ptrObject[T]](ctx context.Context, c client.Client, ns string, labels map[string]string) (O, error) {
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
	if err := c.List(ctx, &lst, client.InNamespace(ns), client.MatchingLabels(labels)); err != nil {
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

func defaultBool(envName string, defVal bool) bool {
	vs := os.Getenv(envName)
	if vs == "" {
		return defVal
	}
	v, _ := opt.Bool(vs).Get()
	return v
}

func defaultEnv(envName, defVal string) string {
	v := os.Getenv(envName)
	if v == "" {
		return defVal
	}
	return v
}

func nameForService(svc *corev1.Service) (string, error) {
	if h, ok := svc.Annotations[AnnotationHostname]; ok {
		if err := dnsname.ValidLabel(h); err != nil {
			return "", fmt.Errorf("invalid Tailscale hostname %q: %w", h, err)
		}
		return h, nil
	}
	return svc.Namespace + "-" + svc.Name, nil
}

func isValidFirewallMode(m string) bool {
	return m == "auto" || m == "nftables" || m == "iptables"
}
