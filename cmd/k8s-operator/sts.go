// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"

	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
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
	"tailscale.com/kube/kubetypes"
	"tailscale.com/net/netutil"
	"tailscale.com/tailcfg"
	"tailscale.com/types/opt"
	"tailscale.com/types/ptr"
	"tailscale.com/util/mak"
)

const (
	// Labels that the operator sets on StatefulSets and Pods. If you add a
	// new label here, do also add it to tailscaleManagedLabels var to
	// ensure that it does not get overwritten by ProxyClass configuration.
	LabelParentType      = "tailscale.com/parent-resource-type"
	LabelParentName      = "tailscale.com/parent-resource"
	LabelParentNamespace = "tailscale.com/parent-resource-ns"

	// LabelProxyClass can be set by users on tailscale Ingresses and Services that define cluster ingress or
	// cluster egress, to specify that configuration in this ProxyClass should be applied to resources created for
	// the Ingress or Service.
	LabelAnnotationProxyClass = "tailscale.com/proxy-class"

	FinalizerName = "tailscale.com/finalizer"

	// Annotations settable by users on services.
	AnnotationExpose             = "tailscale.com/expose"
	AnnotationTags               = "tailscale.com/tags"
	AnnotationHostname           = "tailscale.com/hostname"
	annotationTailnetTargetIPOld = "tailscale.com/ts-tailnet-target-ip"
	AnnotationTailnetTargetIP    = "tailscale.com/tailnet-ip"
	//MagicDNS name of tailnet node.
	AnnotationTailnetTargetFQDN = "tailscale.com/tailnet-fqdn"

	AnnotationProxyGroup = "tailscale.com/proxy-group"

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
	podAnnotationLastSetClusterDNSName    = "tailscale.com/operator-last-set-cluster-dns-name"
	podAnnotationLastSetTailnetTargetIP   = "tailscale.com/operator-last-set-ts-tailnet-target-ip"
	podAnnotationLastSetTailnetTargetFQDN = "tailscale.com/operator-last-set-ts-tailnet-target-fqdn"

	proxyTypeEgress          = "egress_service"
	proxyTypeIngressService  = "ingress_service"
	proxyTypeIngressResource = "ingress_resource"
	proxyTypeConnector       = "connector"
	proxyTypeProxyGroup      = "proxygroup"

	envVarTSLocalAddrPort = "TS_LOCAL_ADDR_PORT"
	defaultLocalAddrPort  = 9002 // metrics and health check port

	letsEncryptStagingEndpoint = "https://acme-staging-v02.api.letsencrypt.org/directory"

	mainContainerName = "tailscale"
)

var (
	// tailscaleManagedLabels are label keys that tailscale operator sets on StatefulSets and Pods.
	tailscaleManagedLabels = []string{kubetypes.LabelManaged, LabelParentType, LabelParentName, LabelParentNamespace, "app"}
	// tailscaleManagedAnnotations are annotation keys that tailscale operator sets on StatefulSets and Pods.
	tailscaleManagedAnnotations = []string{podAnnotationLastSetClusterIP, podAnnotationLastSetTailnetTargetIP, podAnnotationLastSetTailnetTargetFQDN}
)

type tailscaleSTSConfig struct {
	Replicas            int32
	ParentResourceName  string
	ParentResourceUID   string
	ChildResourceLabels map[string]string

	ServeConfig          *ipn.ServeConfig // if serve config is set, this is a proxy for Ingress
	ClusterTargetIP      string           // ingress target IP
	ClusterTargetDNSName string           // ingress target DNS name
	// If set to true, operator should configure containerboot to forward
	// cluster traffic via the proxy set up for Kubernetes Ingress.
	ForwardClusterTrafficViaL7IngressProxy bool

	TailnetTargetIP string // egress target IP

	TailnetTargetFQDN string // egress target FQDN

	Hostname string
	Tags     []string // if empty, use defaultTags

	proxyType string

	// Connector specifies a configuration of a Connector instance if that's
	// what this StatefulSet should be created for.
	Connector *connector

	ProxyClassName string // name of ProxyClass if one needs to be applied to the proxy

	ProxyClass *tsapi.ProxyClass // ProxyClass that needs to be applied to the proxy (if there is one)

	// LoginServer denotes the URL of the control plane that should be used by the proxy.
	LoginServer string

	// HostnamePrefix specifies the desired prefix for the device's hostname. The hostname will be suffixed with the
	// ordinal number generated by the StatefulSet.
	HostnamePrefix string
}

type connector struct {
	// routes is a list of routes that this Connector should advertise either as a subnet router or as an app
	// connector.
	routes string
	// isExitNode defines whether this Connector should act as an exit node.
	isExitNode bool
	// isAppConnector defines whether this Connector should act as an app connector.
	isAppConnector bool
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
	loginServer            string
}

func (sts tailscaleSTSReconciler) validate() error {
	if sts.tsFirewallMode != "" && !isValidFirewallMode(sts.tsFirewallMode) {
		return fmt.Errorf("invalid proxy firewall mode %s, valid modes are iptables, nftables or unset", sts.tsFirewallMode)
	}
	return nil
}

// IsHTTPSEnabledOnTailnet reports whether HTTPS is enabled on the tailnet.
func IsHTTPSEnabledOnTailnet(tsnetServer tsnetServer) bool {
	return len(tsnetServer.CertDomains()) > 0
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

	proxyClass := new(tsapi.ProxyClass)
	if sts.ProxyClassName != "" {
		if err := a.Get(ctx, types.NamespacedName{Name: sts.ProxyClassName}, proxyClass); err != nil {
			return nil, fmt.Errorf("failed to get ProxyClass: %w", err)
		}
		if !tsoperator.ProxyClassIsReady(proxyClass) {
			logger.Infof("ProxyClass %s specified for the proxy, but it is not (yet) in a ready state, waiting..")
			return nil, nil
		}
	}
	sts.ProxyClass = proxyClass

	secretNames, err := a.provisionSecrets(ctx, logger, sts, hsvc)
	if err != nil {
		return nil, fmt.Errorf("failed to create or get API key secret: %w", err)
	}

	_, err = a.reconcileSTS(ctx, logger, sts, hsvc, secretNames)
	if err != nil {
		return nil, fmt.Errorf("failed to reconcile statefulset: %w", err)
	}
	mo := &metricsOpts{
		proxyStsName: hsvc.Name,
		tsNamespace:  hsvc.Namespace,
		proxyLabels:  hsvc.Labels,
		proxyType:    sts.proxyType,
	}
	if err = reconcileMetricsResources(ctx, logger, mo, sts.ProxyClass, a.Client); err != nil {
		return nil, fmt.Errorf("failed to ensure metrics resources: %w", err)
	}
	return hsvc, nil
}

// Cleanup removes all resources associated that were created by Provision with
// the given labels. It returns true when all resources have been removed,
// otherwise it returns false and the caller should retry later.
func (a *tailscaleSTSReconciler) Cleanup(ctx context.Context, logger *zap.SugaredLogger, labels map[string]string, typ string) (done bool, _ error) {
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

		options := []client.DeleteAllOfOption{
			client.InNamespace(a.operatorNamespace),
			client.MatchingLabels(labels),
			client.PropagationPolicy(metav1.DeletePropagationForeground),
		}

		if err = a.DeleteAllOf(ctx, &appsv1.StatefulSet{}, options...); err != nil {
			return false, fmt.Errorf("deleting statefulset: %w", err)
		}

		logger.Debugf("started deletion of statefulset %s/%s", sts.GetNamespace(), sts.GetName())
		return false, nil
	}

	devices, err := a.DeviceInfo(ctx, labels, logger)
	if err != nil {
		return false, fmt.Errorf("getting device info: %w", err)
	}

	for _, dev := range devices {
		if dev.id != "" {
			logger.Debugf("deleting device %s from control", string(dev.id))
			if err = a.tsClient.DeleteDevice(ctx, string(dev.id)); err != nil {
				errResp := &tailscale.ErrResponse{}
				if ok := errors.As(err, errResp); ok && errResp.Status == http.StatusNotFound {
					logger.Debugf("device %s not found, likely because it has already been deleted from control", string(dev.id))
				} else {
					return false, fmt.Errorf("deleting device: %w", err)
				}
			} else {
				logger.Debugf("device %s deleted from control", string(dev.id))
			}
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
	mo := &metricsOpts{
		proxyLabels: labels,
		tsNamespace: a.operatorNamespace,
		proxyType:   typ,
	}
	if err = maybeCleanupMetricsResources(ctx, mo, a.Client); err != nil {
		return false, fmt.Errorf("error cleaning up metrics resources: %w", err)
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
			IPFamilyPolicy: ptr.To(corev1.IPFamilyPolicyPreferDualStack),
		},
	}
	logger.Debugf("reconciling headless service for StatefulSet")
	return createOrUpdate(ctx, a.Client, a.operatorNamespace, hsvc, func(svc *corev1.Service) { svc.Spec = hsvc.Spec })
}

func (a *tailscaleSTSReconciler) provisionSecrets(ctx context.Context, logger *zap.SugaredLogger, stsC *tailscaleSTSConfig, hsvc *corev1.Service) ([]string, error) {
	secretNames := make([]string, stsC.Replicas)

	// Start by ensuring we have Secrets for the desired number of replicas. This will handle both creating and scaling
	// up a StatefulSet.
	for i := range stsC.Replicas {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("%s-%d", hsvc.Name, i),
				Namespace: a.operatorNamespace,
				Labels:    stsC.ChildResourceLabels,
			},
		}

		// If we only have a single replica, use the hostname verbatim. Otherwise, use the hostname prefix and add
		// an ordinal suffix.
		hostname := stsC.Hostname
		if stsC.HostnamePrefix != "" {
			hostname = fmt.Sprintf("%s-%d", stsC.HostnamePrefix, i)
		}

		secretNames[i] = secret.Name

		var orig *corev1.Secret // unmodified copy of secret
		if err := a.Get(ctx, client.ObjectKeyFromObject(secret), secret); err == nil {
			logger.Debugf("secret %s/%s already exists", secret.GetNamespace(), secret.GetName())
			orig = secret.DeepCopy()
		} else if !apierrors.IsNotFound(err) {
			return nil, err
		}

		var (
			authKey string
			err     error
		)
		if orig == nil {
			// Create API Key secret which is going to be used by the statefulset
			// to authenticate with Tailscale.
			logger.Debugf("creating authkey for new tailscale proxy")
			tags := stsC.Tags
			if len(tags) == 0 {
				tags = a.defaultTags
			}
			authKey, err = newAuthKey(ctx, a.tsClient, tags)
			if err != nil {
				return nil, err
			}
		}

		configs, err := tailscaledConfig(stsC, authKey, orig, hostname)
		if err != nil {
			return nil, fmt.Errorf("error creating tailscaled config: %w", err)
		}

		latest := tailcfg.CapabilityVersion(-1)
		var latestConfig ipn.ConfigVAlpha
		for key, val := range configs {
			fn := tsoperator.TailscaledConfigFileName(key)
			b, err := json.Marshal(val)
			if err != nil {
				return nil, fmt.Errorf("error marshalling tailscaled config: %w", err)
			}

			mak.Set(&secret.StringData, fn, string(b))
			if key > latest {
				latest = key
				latestConfig = val
			}
		}

		if stsC.ServeConfig != nil {
			j, err := json.Marshal(stsC.ServeConfig)
			if err != nil {
				return nil, err
			}

			mak.Set(&secret.StringData, "serve-config", string(j))
		}

		if orig != nil && !apiequality.Semantic.DeepEqual(latest, orig) {
			logger.With("config", sanitizeConfig(latestConfig)).Debugf("patching the existing proxy Secret")
			if err = a.Patch(ctx, secret, client.MergeFrom(orig)); err != nil {
				return nil, err
			}
		} else {
			logger.With("config", sanitizeConfig(latestConfig)).Debugf("creating a new Secret for the proxy")
			if err = a.Create(ctx, secret); err != nil {
				return nil, err
			}
		}
	}

	// Next, we check if we have additional secrets and remove them and their associated device. This happens when we
	// scale an StatefulSet down.
	var secrets corev1.SecretList
	if err := a.List(ctx, &secrets, client.InNamespace(a.operatorNamespace), client.MatchingLabels(stsC.ChildResourceLabels)); err != nil {
		return nil, err
	}

	for _, secret := range secrets.Items {
		var ordinal int32
		if _, err := fmt.Sscanf(secret.Name, hsvc.Name+"-%d", &ordinal); err != nil {
			return nil, err
		}

		if ordinal < stsC.Replicas {
			continue
		}

		dev, err := deviceInfo(&secret, "", logger)
		if err != nil {
			return nil, err
		}

		if dev != nil && dev.id != "" {
			var errResp *tailscale.ErrResponse

			err = a.tsClient.DeleteDevice(ctx, string(dev.id))
			switch {
			case errors.As(err, &errResp) && errResp.Status == http.StatusNotFound:
				// This device has possibly already been deleted in the admin console. So we can ignore this
				// and move on to removing the secret.
			case err != nil:
				return nil, err
			}
		}

		if err = a.Delete(ctx, &secret); err != nil {
			return nil, err
		}
	}

	return secretNames, nil
}

// sanitizeConfig returns an ipn.ConfigVAlpha with sensitive fields redacted. Since we pump everything
// into JSON-encoded logs it's easier to read this with a .With method than converting it to a string.
func sanitizeConfig(c ipn.ConfigVAlpha) ipn.ConfigVAlpha {
	// Explicitly redact AuthKey because we never want it appearing in logs. Never populate this with the
	// actual auth key.
	if c.AuthKey != nil {
		c.AuthKey = ptr.To("**redacted**")
	}

	return c
}

// DeviceInfo returns the device ID, hostname, IPs and capver for the Tailscale device that acts as an operator proxy.
// It retrieves info from a Kubernetes Secret labeled with the provided labels. Capver is cross-validated against the
// Pod to ensure that it is the currently running Pod that set the capver. If the Pod or the Secret does not exist, the
// returned capver is -1. Either of device ID, hostname and IPs can be empty string if not found in the Secret.
func (a *tailscaleSTSReconciler) DeviceInfo(ctx context.Context, childLabels map[string]string, logger *zap.SugaredLogger) ([]*device, error) {
	var secrets corev1.SecretList
	if err := a.List(ctx, &secrets, client.InNamespace(a.operatorNamespace), client.MatchingLabels(childLabels)); err != nil {
		return nil, err
	}

	devices := make([]*device, 0)
	for _, sec := range secrets.Items {
		podUID := ""
		pod := new(corev1.Pod)
		err := a.Get(ctx, types.NamespacedName{Namespace: sec.Namespace, Name: sec.Name}, pod)
		switch {
		case apierrors.IsNotFound(err):
			// If the Pod is not found, we won't have its UID. We can still get the device information but the
			// capability version will be unknown.
		case err != nil:
			return nil, err
		default:
			podUID = string(pod.ObjectMeta.UID)
		}

		info, err := deviceInfo(&sec, podUID, logger)
		if err != nil {
			return nil, err
		}

		if info != nil {
			devices = append(devices, info)
		}
	}

	return devices, nil
}

// device contains tailscale state of a proxy device as gathered from its tailscale state Secret.
type device struct {
	id       tailcfg.StableNodeID // device's stable ID
	hostname string               // MagicDNS name of the device
	ips      []string             // Tailscale IPs of the device
	// ingressDNSName is the L7 Ingress DNS name. In practice this will be the same value as hostname, but only set
	// when the device has been configured to serve traffic on it via 'tailscale serve'.
	ingressDNSName string
	capver         tailcfg.CapabilityVersion
}

func deviceInfo(sec *corev1.Secret, podUID string, log *zap.SugaredLogger) (dev *device, err error) {
	id := tailcfg.StableNodeID(sec.Data[kubetypes.KeyDeviceID])
	if id == "" {
		return dev, nil
	}
	dev = &device{id: id}
	// Kubernetes chokes on well-formed FQDNs with the trailing dot, so we have
	// to remove it.
	dev.hostname = strings.TrimSuffix(string(sec.Data[kubetypes.KeyDeviceFQDN]), ".")
	if dev.hostname == "" {
		// Device ID gets stored and retrieved in a different flow than
		// FQDN and IPs. A device that acts as Kubernetes operator
		// proxy, but whose route setup has failed might have a device
		// ID, but no FQDN/IPs. If so, return the ID, to allow the
		// operator to clean up such devices.
		return dev, nil
	}
	dev.ingressDNSName = dev.hostname
	pcv := proxyCapVer(sec, podUID, log)
	dev.capver = pcv
	// TODO(irbekrm): we fall back to using the hostname field to determine Ingress's hostname to ensure backwards
	// compatibility. In 1.82 we can remove this fallback mechanism.
	if pcv >= 109 {
		dev.ingressDNSName = strings.TrimSuffix(string(sec.Data[kubetypes.KeyHTTPSEndpoint]), ".")
		if strings.EqualFold(dev.ingressDNSName, kubetypes.ValueNoHTTPS) {
			dev.ingressDNSName = ""
		}
	}
	if rawDeviceIPs, ok := sec.Data[kubetypes.KeyDeviceIPs]; ok {
		ips := make([]string, 0)
		if err := json.Unmarshal(rawDeviceIPs, &ips); err != nil {
			return nil, err
		}
		dev.ips = ips
	}
	return dev, nil
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

//go:embed deploy/manifests/proxy.yaml
var proxyYaml []byte

//go:embed deploy/manifests/userspace-proxy.yaml
var userspaceProxyYaml []byte

func (a *tailscaleSTSReconciler) reconcileSTS(ctx context.Context, logger *zap.SugaredLogger, sts *tailscaleSTSConfig, headlessSvc *corev1.Service, proxySecrets []string) (*appsv1.StatefulSet, error) {
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

	if sts.Replicas > 0 {
		ss.Spec.Replicas = ptr.To(sts.Replicas)
	}

	// Generic containerboot configuration options.
	container.Env = append(container.Env,
		corev1.EnvVar{
			Name:  "TS_KUBE_SECRET",
			Value: "$(POD_NAME)",
		},
		corev1.EnvVar{
			Name:  "TS_EXPERIMENTAL_VERSIONED_CONFIG_DIR",
			Value: "/etc/tsconfig/$(POD_NAME)",
		},
	)

	if sts.ForwardClusterTrafficViaL7IngressProxy {
		container.Env = append(container.Env, corev1.EnvVar{
			Name:  "EXPERIMENTAL_ALLOW_PROXYING_CLUSTER_TRAFFIC_VIA_INGRESS",
			Value: "true",
		})
	}

	for i, secret := range proxySecrets {
		configVolume := corev1.Volume{
			Name: "tailscaledconfig-" + strconv.Itoa(i),
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: secret,
				},
			},
		}

		pod.Spec.Volumes = append(ss.Spec.Template.Spec.Volumes, configVolume)
		container.VolumeMounts = append(container.VolumeMounts, corev1.VolumeMount{
			Name:      fmt.Sprintf("tailscaledconfig-%d", i),
			ReadOnly:  true,
			MountPath: path.Join("/etc/tsconfig/", secret),
		})
	}

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
	} else if sts.ClusterTargetDNSName != "" {
		container.Env = append(container.Env, corev1.EnvVar{
			Name:  "TS_EXPERIMENTAL_DEST_DNS_NAME",
			Value: sts.ClusterTargetDNSName,
		})
		mak.Set(&ss.Spec.Template.Annotations, podAnnotationLastSetClusterDNSName, sts.ClusterTargetDNSName)
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
			Value: "/etc/tailscaled/$(POD_NAME)/serve-config",
		})

		for i, secret := range proxySecrets {
			container.VolumeMounts = append(container.VolumeMounts, corev1.VolumeMount{
				Name:      "serve-config-" + strconv.Itoa(i),
				ReadOnly:  true,
				MountPath: path.Join("/etc/tailscaled", secret),
			})

			pod.Spec.Volumes = append(ss.Spec.Template.Spec.Volumes, corev1.Volume{
				Name: "serve-config-" + strconv.Itoa(i),
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: secret,
						Items:      []corev1.KeyToPath{{Key: "serve-config", Path: "serve-config"}},
					},
				},
			})
		}

	}

	app, err := appInfoForProxy(sts)
	if err != nil {
		// No need to error out if now or in future we end up in a
		// situation where app info cannot be determined for one of the
		// many proxy configurations that the operator can produce.
		logger.Error("[unexpected] unable to determine proxy type")
	} else {
		container.Env = append(container.Env, corev1.EnvVar{
			Name:  "TS_INTERNAL_APP",
			Value: app,
		})
	}
	logger.Debugf("reconciling statefulset %s/%s", ss.GetNamespace(), ss.GetName())
	if sts.ProxyClassName != "" {
		logger.Debugf("configuring proxy resources with ProxyClass %s", sts.ProxyClassName)
		ss = applyProxyClassToStatefulSet(sts.ProxyClass, ss, sts, logger)
	}
	updateSS := func(s *appsv1.StatefulSet) {
		s.Spec = ss.Spec
		s.ObjectMeta.Labels = ss.Labels
		s.ObjectMeta.Annotations = ss.Annotations
	}
	return createOrUpdate(ctx, a.Client, a.operatorNamespace, ss, updateSS)
}

func appInfoForProxy(cfg *tailscaleSTSConfig) (string, error) {
	if cfg.ClusterTargetDNSName != "" || cfg.ClusterTargetIP != "" {
		return kubetypes.AppIngressProxy, nil
	}
	if cfg.TailnetTargetFQDN != "" || cfg.TailnetTargetIP != "" {
		return kubetypes.AppEgressProxy, nil
	}
	if cfg.ServeConfig != nil {
		return kubetypes.AppIngressResource, nil
	}
	if cfg.Connector != nil {
		return kubetypes.AppConnector, nil
	}
	return "", errors.New("unable to determine proxy type")
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

func debugSetting(pc *tsapi.ProxyClass) bool {
	if pc == nil ||
		pc.Spec.StatefulSet == nil ||
		pc.Spec.StatefulSet.Pod == nil ||
		pc.Spec.StatefulSet.Pod.TailscaleContainer == nil ||
		pc.Spec.StatefulSet.Pod.TailscaleContainer.Debug == nil {
		// This default will change to false in 1.82.0.
		return pc.Spec.Metrics != nil && pc.Spec.Metrics.Enable
	}

	return pc.Spec.StatefulSet.Pod.TailscaleContainer.Debug.Enable
}

func applyProxyClassToStatefulSet(pc *tsapi.ProxyClass, ss *appsv1.StatefulSet, stsCfg *tailscaleSTSConfig, logger *zap.SugaredLogger) *appsv1.StatefulSet {
	if pc == nil || ss == nil {
		return ss
	}

	metricsEnabled := pc.Spec.Metrics != nil && pc.Spec.Metrics.Enable
	debugEnabled := debugSetting(pc)
	if metricsEnabled || debugEnabled {
		isEgress := stsCfg != nil && (stsCfg.TailnetTargetFQDN != "" || stsCfg.TailnetTargetIP != "")
		isForwardingL7Ingress := stsCfg != nil && stsCfg.ForwardClusterTrafficViaL7IngressProxy
		if isEgress {
			// TODO (irbekrm): fix this
			// For Ingress proxies that have been configured with
			// tailscale.com/experimental-forward-cluster-traffic-via-ingress
			// annotation, all cluster traffic is forwarded to the
			// Ingress backend(s).
			logger.Info("ProxyClass specifies that metrics should be enabled, but this is currently not supported for egress proxies.")
		} else if isForwardingL7Ingress {
			// TODO (irbekrm): fix this
			// For egress proxies, currently all cluster traffic is forwarded to the tailnet target.
			logger.Info("ProxyClass specifies that metrics should be enabled, but this is currently not supported for Ingress proxies that accept cluster traffic.")
		} else {
			enableEndpoints(ss, metricsEnabled, debugEnabled)
		}
	}

	if stsCfg != nil {
		usesLetsEncrypt := stsCfg.proxyType == proxyTypeIngressResource ||
			stsCfg.proxyType == string(tsapi.ProxyGroupTypeIngress) ||
			stsCfg.proxyType == string(tsapi.ProxyGroupTypeKubernetesAPIServer)

		if pc.Spec.UseLetsEncryptStagingEnvironment && usesLetsEncrypt {
			for i, c := range ss.Spec.Template.Spec.Containers {
				if isMainContainer(&c) {
					ss.Spec.Template.Spec.Containers[i].Env = append(ss.Spec.Template.Spec.Containers[i].Env, corev1.EnvVar{
						Name:  "TS_DEBUG_ACME_DIRECTORY_URL",
						Value: letsEncryptStagingEndpoint,
					})
					break
				}
			}
		}
	}

	if pc.Spec.StatefulSet == nil {
		return ss
	}

	// Update StatefulSet metadata.
	if wantsSSLabels := pc.Spec.StatefulSet.Labels.Parse(); len(wantsSSLabels) > 0 {
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
	if wantsPodLabels := wantsPod.Labels.Parse(); len(wantsPodLabels) > 0 {
		ss.Spec.Template.ObjectMeta.Labels = mergeStatefulSetLabelsOrAnnots(ss.Spec.Template.ObjectMeta.Labels, wantsPodLabels, tailscaleManagedLabels)
	}
	if wantsPodAnnots := wantsPod.Annotations; len(wantsPodAnnots) > 0 {
		ss.Spec.Template.ObjectMeta.Annotations = mergeStatefulSetLabelsOrAnnots(ss.Spec.Template.ObjectMeta.Annotations, wantsPodAnnots, tailscaleManagedAnnotations)
	}
	ss.Spec.Template.Spec.SecurityContext = wantsPod.SecurityContext
	ss.Spec.Template.Spec.ImagePullSecrets = wantsPod.ImagePullSecrets
	ss.Spec.Template.Spec.NodeName = wantsPod.NodeName
	ss.Spec.Template.Spec.NodeSelector = wantsPod.NodeSelector
	ss.Spec.Template.Spec.Affinity = wantsPod.Affinity
	ss.Spec.Template.Spec.Tolerations = wantsPod.Tolerations
	ss.Spec.Template.Spec.PriorityClassName = wantsPod.PriorityClassName
	ss.Spec.Template.Spec.TopologySpreadConstraints = wantsPod.TopologySpreadConstraints

	// Update containers.
	updateContainer := func(overlay *tsapi.Container, base corev1.Container) corev1.Container {
		if overlay == nil {
			return base
		}
		if overlay.SecurityContext != nil {
			base.SecurityContext = overlay.SecurityContext
		}
		base.Resources = overlay.Resources
		for _, e := range overlay.Env {
			// Env vars configured via ProxyClass might override env
			// vars that have been specified by the operator, i.e
			// TS_USERSPACE. The intended behaviour is to allow this
			// and in practice it works without explicitly removing
			// the operator configured value here as a later value
			// in the env var list overrides an earlier one.
			base.Env = append(base.Env, corev1.EnvVar{Name: string(e.Name), Value: e.Value})
		}
		if overlay.Image != "" {
			base.Image = overlay.Image
		}
		if overlay.ImagePullPolicy != "" {
			base.ImagePullPolicy = overlay.ImagePullPolicy
		}
		return base
	}
	for i, c := range ss.Spec.Template.Spec.Containers {
		if isMainContainer(&c) {
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

func enableEndpoints(ss *appsv1.StatefulSet, metrics, debug bool) {
	for i, c := range ss.Spec.Template.Spec.Containers {
		if isMainContainer(&c) {
			if debug {
				ss.Spec.Template.Spec.Containers[i].Env = append(ss.Spec.Template.Spec.Containers[i].Env,
					// Serve tailscaled's debug metrics on on
					// <pod-ip>:9001/debug/metrics. If we didn't specify Pod IP
					// here, the proxy would, in some cases, also listen to its
					// Tailscale IP- we don't want folks to start relying on this
					// side-effect as a feature.
					corev1.EnvVar{
						Name:  "TS_DEBUG_ADDR_PORT",
						Value: "$(POD_IP):9001",
					},
					// TODO(tomhjp): Can remove this env var once 1.76.x is no
					// longer supported.
					corev1.EnvVar{
						Name:  "TS_TAILSCALED_EXTRA_ARGS",
						Value: "--debug=$(TS_DEBUG_ADDR_PORT)",
					},
				)

				ss.Spec.Template.Spec.Containers[i].Ports = append(ss.Spec.Template.Spec.Containers[i].Ports,
					corev1.ContainerPort{
						Name:          "debug",
						Protocol:      "TCP",
						ContainerPort: 9001,
					},
				)
			}

			if metrics {
				ss.Spec.Template.Spec.Containers[i].Env = append(ss.Spec.Template.Spec.Containers[i].Env,
					// Serve client metrics on <pod-ip>:9002/metrics.
					corev1.EnvVar{
						Name:  "TS_LOCAL_ADDR_PORT",
						Value: "$(POD_IP):9002",
					},
					corev1.EnvVar{
						Name:  "TS_ENABLE_METRICS",
						Value: "true",
					},
				)
				ss.Spec.Template.Spec.Containers[i].Ports = append(ss.Spec.Template.Spec.Containers[i].Ports,
					corev1.ContainerPort{
						Name:          "metrics",
						Protocol:      "TCP",
						ContainerPort: 9002,
					},
				)
			}

			break
		}
	}
}

func isMainContainer(c *corev1.Container) bool {
	return c.Name == mainContainerName
}

// tailscaledConfig takes a proxy config, a newly generated auth key if generated and a Secret with the previous proxy
// state and auth key and returns tailscaled config files for currently supported proxy versions.
func tailscaledConfig(stsC *tailscaleSTSConfig, newAuthkey string, oldSecret *corev1.Secret, hostname string) (tailscaledConfigs, error) {
	conf := &ipn.ConfigVAlpha{
		Version:             "alpha0",
		AcceptDNS:           "false",
		AcceptRoutes:        "false", // AcceptRoutes defaults to true
		Locked:              "false",
		Hostname:            &hostname,
		NoStatefulFiltering: "true", // Explicitly enforce default value, see #14216
		AppConnector:        &ipn.AppConnectorPrefs{Advertise: false},
	}

	if stsC.LoginServer != "" {
		conf.ServerURL = &stsC.LoginServer
	}

	if stsC.Connector != nil {
		routes, err := netutil.CalcAdvertiseRoutes(stsC.Connector.routes, stsC.Connector.isExitNode)
		if err != nil {
			return nil, fmt.Errorf("error calculating routes: %w", err)
		}
		conf.AdvertiseRoutes = routes
		if stsC.Connector.isAppConnector {
			conf.AppConnector.Advertise = true
		}
	}
	if shouldAcceptRoutes(stsC.ProxyClass) {
		conf.AcceptRoutes = "true"
	}

	if newAuthkey != "" {
		conf.AuthKey = &newAuthkey
	} else if shouldRetainAuthKey(oldSecret) {
		key, err := authKeyFromSecret(oldSecret)
		if err != nil {
			return nil, fmt.Errorf("error retrieving auth key from Secret: %w", err)
		}
		conf.AuthKey = key
	}

	capVerConfigs := make(map[tailcfg.CapabilityVersion]ipn.ConfigVAlpha)
	capVerConfigs[107] = *conf

	// AppConnector config option is only understood by clients of capver 107 and newer.
	conf.AppConnector = nil
	capVerConfigs[95] = *conf
	return capVerConfigs, nil
}

// latestConfigFromSecret returns the ipn.ConfigVAlpha with the highest capver
// as found in the Secret's key names, e.g. "cap-107.hujson" has capver 107.
// If no config is found, it returns nil.
func latestConfigFromSecret(s *corev1.Secret) (*ipn.ConfigVAlpha, error) {
	latest := tailcfg.CapabilityVersion(-1)
	latestStr := ""
	for k, data := range s.Data {
		// write to StringData, read from Data as StringData is write-only
		if len(data) == 0 {
			continue
		}
		v, err := tsoperator.CapVerFromFileName(k)
		if err != nil {
			continue
		}
		if v > latest {
			latestStr = k
			latest = v
		}
	}

	var conf *ipn.ConfigVAlpha
	if latestStr != "" {
		conf = &ipn.ConfigVAlpha{}
		if err := json.Unmarshal([]byte(s.Data[latestStr]), conf); err != nil {
			return nil, fmt.Errorf("error unmarshaling tailscaled config from Secret %q in field %q: %w", s.Name, latestStr, err)
		}
	}

	return conf, nil
}

func authKeyFromSecret(s *corev1.Secret) (key *string, err error) {
	conf, err := latestConfigFromSecret(s)
	if err != nil {
		return nil, err
	}

	// Allow for configs that don't contain an auth key. Perhaps
	// users have some mechanisms to delete them. Auth key is
	// normally not needed after the initial login.
	if conf != nil {
		key = conf.AuthKey
	}

	return key, nil
}

// shouldRetainAuthKey returns true if the state stored in a proxy's state Secret suggests that auth key should be
// retained (because the proxy has not yet successfully authenticated).
func shouldRetainAuthKey(s *corev1.Secret) bool {
	if s == nil {
		return false // nothing to retain here
	}
	return len(s.Data["device_id"]) == 0 // proxy has not authed yet
}

func shouldAcceptRoutes(pc *tsapi.ProxyClass) bool {
	return pc != nil && pc.Spec.TailscaleConfig != nil && pc.Spec.TailscaleConfig.AcceptRoutes
}

// ptrObject is a type constraint for pointer types that implement
// client.Object.
type ptrObject[T any] interface {
	client.Object
	*T
}

type tailscaledConfigs map[tailcfg.CapabilityVersion]ipn.ConfigVAlpha

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

func nameForService(svc *corev1.Service) string {
	if h, ok := svc.Annotations[AnnotationHostname]; ok {
		return h
	}
	return svc.Namespace + "-" + svc.Name
}

// proxyClassForObject returns the proxy class for the given object. If the
// object does not have a proxy class label, it returns the default proxy class
func proxyClassForObject(o client.Object, proxyDefaultClass string) string {
	proxyClass, exists := o.GetLabels()[LabelAnnotationProxyClass]
	if exists {
		return proxyClass
	}

	proxyClass, exists = o.GetAnnotations()[LabelAnnotationProxyClass]
	if exists {
		return proxyClass
	}

	return proxyDefaultClass
}

func isValidFirewallMode(m string) bool {
	return m == "auto" || m == "nftables" || m == "iptables"
}

// proxyCapVer accepts a proxy state Secret and UID of the current proxy Pod returns the capability version of the
// tailscale running in that Pod. This is best effort - if the capability version can not (currently) be determined, it
// returns -1.
func proxyCapVer(sec *corev1.Secret, podUID string, log *zap.SugaredLogger) tailcfg.CapabilityVersion {
	if sec == nil || podUID == "" {
		return tailcfg.CapabilityVersion(-1)
	}
	if len(sec.Data[kubetypes.KeyCapVer]) == 0 || len(sec.Data[kubetypes.KeyPodUID]) == 0 {
		return tailcfg.CapabilityVersion(-1)
	}
	capVer, err := strconv.Atoi(string(sec.Data[kubetypes.KeyCapVer]))
	if err != nil {
		log.Infof("[unexpected]: unexpected capability version in proxy's state Secret, expected an integer, got %q", string(sec.Data[kubetypes.KeyCapVer]))
		return tailcfg.CapabilityVersion(-1)
	}
	if !strings.EqualFold(podUID, string(sec.Data[kubetypes.KeyPodUID])) {
		return tailcfg.CapabilityVersion(-1)
	}
	return tailcfg.CapabilityVersion(capVer)
}
