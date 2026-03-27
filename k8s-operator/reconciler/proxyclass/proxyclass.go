// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// Package proxyclass provides reconciliation logic for the ProxyClass custom resource definition. It is responsible for
// validating ProxyClass specs and setting their status conditions accordingly.
package proxyclass

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

	dockerref "github.com/distribution/reference"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apivalidation "k8s.io/apimachinery/pkg/api/validation"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	metavalidation "k8s.io/apimachinery/pkg/apis/meta/v1/validation"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	tsoperator "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/k8s-operator/reconciler"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tstime"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/set"
)

const (
	reconcilerName = "proxyclass-reconciler"

	// ServiceMonitorCRD is the name of the Prometheus ServiceMonitor CustomResourceDefinition.
	ServiceMonitorCRD = "servicemonitors.monitoring.coreos.com"

	// ReasonProxyClassValid is the condition reason used when a ProxyClass is valid and ready.
	ReasonProxyClassValid = "ProxyClassValid"

	reasonProxyClassInvalid  = "ProxyClassInvalid"
	reasonCustomTSEnvVar     = "CustomTSEnvVar"
	messageProxyClassInvalid = "ProxyClass is not valid: %v"
	messageCustomTSEnvVar    = "ProxyClass overrides the default value for %s env var for %s container. Running with custom values for Tailscale env vars is not recommended and might break in the future."

	testSvcName        = "test-node-port-range"
	invalidSvcNodePort = 777777
)

// gaugeProxyClassResources tracks the number of ProxyClass resources that we're currently managing.
var gaugeProxyClassResources = clientmetric.NewGauge("k8s_proxyclass_resources")

type (
	// Reconciler is a reconcile.Reconciler implementation used to manage the reconciliation of ProxyClass custom
	// resources.
	Reconciler struct {
		client.Client

		recorder    record.EventRecorder
		logger      *zap.SugaredLogger
		clock       tstime.Clock
		tsNamespace string

		mu sync.Mutex // protects following

		// managedProxyClasses is a set of all ProxyClass resources that we're currently
		// managing. This is only used for metrics.
		managedProxyClasses set.Slice[types.UID]
		// nodePortRange is the NodePort range set for the Kubernetes Cluster. This is used
		// when validating port ranges configured by users for spec.StaticEndpoints
		nodePortRange *tsapi.PortRange
	}

	// ReconcilerOptions contains configuration values for the Reconciler.
	ReconcilerOptions struct {
		// Client is used to interact with the Kubernetes API.
		Client client.Client
		// Recorder is used to emit Kubernetes events.
		Recorder record.EventRecorder
		// TailscaleNamespace is the namespace the operator is installed in.
		TailscaleNamespace string
		// Clock controls time-based functions. Typically modified for tests.
		Clock tstime.Clock
		// Logger is the logger to use for this Reconciler.
		Logger *zap.SugaredLogger
	}
)

// NewReconciler returns a new instance of the Reconciler type. It also attempts to determine the
// cluster's NodePort range by probing the Kubernetes API, which is used to validate port ranges
// in ProxyClass.Spec.StaticEndpoints.
func NewReconciler(options ReconcilerOptions) *Reconciler {
	logger := options.Logger.Named(reconcilerName)
	return &Reconciler{
		Client:        options.Client,
		nodePortRange: getServicesNodePortRange(context.Background(), options.Client, options.TailscaleNamespace, logger),
		recorder:      options.Recorder,
		tsNamespace:   options.TailscaleNamespace,
		clock:         options.Clock,
		logger:        logger,
	}
}

// Register registers the Reconciler onto the given manager.Manager. It also sets up a Watch on
// CustomResourceDefinition changes so that ProxyClasses that define a ServiceMonitor get reconciled
// when the ServiceMonitor CRD is applied.
func (r *Reconciler) Register(mgr manager.Manager) error {
	serviceMonitorFilter := handler.EnqueueRequestsFromMapFunc(proxyClassesWithServiceMonitor(r.Client, r.logger))
	return builder.
		ControllerManagedBy(mgr).
		For(&tsapi.ProxyClass{}).
		Named(reconcilerName).
		Watches(&apiextensionsv1.CustomResourceDefinition{}, serviceMonitorFilter).
		Complete(r)
}

func (r *Reconciler) Reconcile(ctx context.Context, req reconcile.Request) (res reconcile.Result, err error) {
	logger := r.logger.With("ProxyClass", req.Name)
	logger.Debugf("starting reconcile")
	defer logger.Debugf("reconcile finished")

	pc := new(tsapi.ProxyClass)
	err = r.Get(ctx, req.NamespacedName, pc)
	if apierrors.IsNotFound(err) {
		logger.Debugf("ProxyClass not found, assuming it was deleted")
		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to get tailscale.com ProxyClass: %w", err)
	}
	if !pc.DeletionTimestamp.IsZero() {
		logger.Debugf("ProxyClass is being deleted")
		return reconcile.Result{}, r.maybeCleanup(ctx, logger, pc)
	}

	// Add a finalizer so that we can ensure that metrics get updated when
	// this ProxyClass is deleted.
	if !slices.Contains(pc.Finalizers, reconciler.FinalizerName) {
		logger.Debugf("updating ProxyClass finalizers")
		pc.Finalizers = append(pc.Finalizers, reconciler.FinalizerName)
		if err := r.Update(ctx, pc); err != nil {
			return res, fmt.Errorf("failed to add finalizer: %w", err)
		}
	}

	// Ensure this ProxyClass is tracked in metrics.
	r.mu.Lock()
	r.managedProxyClasses.Add(pc.UID)
	gaugeProxyClassResources.Set(int64(r.managedProxyClasses.Len()))
	r.mu.Unlock()

	oldPCStatus := pc.Status.DeepCopy()
	if errs := r.validate(ctx, pc, logger); errs != nil {
		msg := fmt.Sprintf(messageProxyClassInvalid, errs.ToAggregate().Error())
		r.recorder.Event(pc, corev1.EventTypeWarning, reasonProxyClassInvalid, msg)
		tsoperator.SetProxyClassCondition(pc, tsapi.ProxyClassReady, metav1.ConditionFalse, reasonProxyClassInvalid, msg, pc.Generation, r.clock, logger)
	} else {
		tsoperator.SetProxyClassCondition(pc, tsapi.ProxyClassReady, metav1.ConditionTrue, ReasonProxyClassValid, ReasonProxyClassValid, pc.Generation, r.clock, logger)
	}
	if !apiequality.Semantic.DeepEqual(oldPCStatus, &pc.Status) {
		if err := r.Client.Status().Update(ctx, pc); err != nil {
			logger.Errorf("error updating ProxyClass status: %v", err)
			return reconcile.Result{}, err
		}
	}
	return reconcile.Result{}, nil
}

func (r *Reconciler) validate(ctx context.Context, pc *tsapi.ProxyClass, logger *zap.SugaredLogger) (violations field.ErrorList) {
	if sts := pc.Spec.StatefulSet; sts != nil {
		if len(sts.Labels) > 0 {
			if errs := metavalidation.ValidateLabels(sts.Labels.Parse(), field.NewPath(".spec.statefulSet.labels")); errs != nil {
				violations = append(violations, errs...)
			}
		}
		if len(sts.Annotations) > 0 {
			if errs := apivalidation.ValidateAnnotations(sts.Annotations, field.NewPath(".spec.statefulSet.annotations")); errs != nil {
				violations = append(violations, errs...)
			}
		}
		if pod := sts.Pod; pod != nil {
			if len(pod.Labels) > 0 {
				if errs := metavalidation.ValidateLabels(pod.Labels.Parse(), field.NewPath(".spec.statefulSet.pod.labels")); errs != nil {
					violations = append(violations, errs...)
				}
			}
			if len(pod.Annotations) > 0 {
				if errs := apivalidation.ValidateAnnotations(pod.Annotations, field.NewPath(".spec.statefulSet.pod.annotations")); errs != nil {
					violations = append(violations, errs...)
				}
			}
			if tc := pod.TailscaleContainer; tc != nil {
				for _, e := range tc.Env {
					if strings.HasPrefix(string(e.Name), "TS_") {
						r.recorder.Event(pc, corev1.EventTypeWarning, reasonCustomTSEnvVar, fmt.Sprintf(messageCustomTSEnvVar, string(e.Name), "tailscale"))
					}
					if strings.EqualFold(string(e.Name), "EXPERIMENTAL_TS_CONFIGFILE_PATH") {
						r.recorder.Event(pc, corev1.EventTypeWarning, reasonCustomTSEnvVar, fmt.Sprintf(messageCustomTSEnvVar, string(e.Name), "tailscale"))
					}
					if strings.EqualFold(string(e.Name), "EXPERIMENTAL_ALLOW_PROXYING_CLUSTER_TRAFFIC_VIA_INGRESS") {
						r.recorder.Event(pc, corev1.EventTypeWarning, reasonCustomTSEnvVar, fmt.Sprintf(messageCustomTSEnvVar, string(e.Name), "tailscale"))
					}
				}
				if tc.Image != "" {
					// Same validation as used by kubelet https://github.com/kubernetes/kubernetes/blob/release-1.30/pkg/kubelet/images/image_manager.go#L212
					if _, err := dockerref.ParseNormalizedNamed(tc.Image); err != nil {
						violations = append(violations, field.TypeInvalid(field.NewPath("spec", "statefulSet", "pod", "tailscaleContainer", "image"), tc.Image, err.Error()))
					}
				}
			}
			if tc := pod.TailscaleInitContainer; tc != nil {
				if tc.Image != "" {
					// Same validation as used by kubelet https://github.com/kubernetes/kubernetes/blob/release-1.30/pkg/kubelet/images/image_manager.go#L212
					if _, err := dockerref.ParseNormalizedNamed(tc.Image); err != nil {
						violations = append(violations, field.TypeInvalid(field.NewPath("spec", "statefulSet", "pod", "tailscaleInitContainer", "image"), tc.Image, err.Error()))
					}
				}

				if tc.Debug != nil {
					violations = append(violations, field.TypeInvalid(field.NewPath("spec", "statefulSet", "pod", "tailscaleInitContainer", "debug"), tc.Debug, "debug settings cannot be configured on the init container"))
				}
			}
		}
	}
	if pc.Spec.Metrics != nil && pc.Spec.Metrics.ServiceMonitor != nil && pc.Spec.Metrics.ServiceMonitor.Enable {
		found, err := hasServiceMonitorCRD(ctx, r.Client)
		if err != nil {
			r.logger.Infof("[unexpected]: error retrieving %q CRD: %v", ServiceMonitorCRD, err)
			// best effort validation - don't error out here
		} else if !found {
			msg := fmt.Sprintf("ProxyClass defines that a ServiceMonitor custom resource should be created, but %q CRD was not found", ServiceMonitorCRD)
			violations = append(violations, field.TypeInvalid(field.NewPath("spec", "metrics", "serviceMonitor"), "enable", msg))
		}
	}
	if pc.Spec.Metrics != nil && pc.Spec.Metrics.ServiceMonitor != nil && len(pc.Spec.Metrics.ServiceMonitor.Labels) > 0 {
		if errs := metavalidation.ValidateLabels(pc.Spec.Metrics.ServiceMonitor.Labels.Parse(), field.NewPath(".spec.metrics.serviceMonitor.labels")); errs != nil {
			violations = append(violations, errs...)
		}
	}

	if stat := pc.Spec.StaticEndpoints; stat != nil {
		if err := validateNodePortRanges(ctx, r.Client, r.nodePortRange, pc); err != nil {
			var prs tsapi.PortRanges = stat.NodePort.Ports
			violations = append(violations, field.TypeInvalid(field.NewPath("spec", "staticEndpoints", "nodePort", "ports"), prs.String(), err.Error()))
		}

		if len(stat.NodePort.Selector) < 1 {
			logger.Debug("no Selectors specified on `spec.staticEndpoints.nodePort.selectors` field")
		}
	}
	// We do not validate embedded fields (security context, resource
	// requirements etc) as we inherit upstream validation for those fields.
	// Invalid values would get rejected by upstream validations at apply
	// time.
	return violations
}

func hasServiceMonitorCRD(ctx context.Context, cl client.Client) (bool, error) {
	sm := &apiextensionsv1.CustomResourceDefinition{}
	if err := cl.Get(ctx, types.NamespacedName{Name: ServiceMonitorCRD}, sm); apierrors.IsNotFound(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}

// maybeCleanup removes tailscale.com finalizer and ensures that the ProxyClass
// is no longer counted towards k8s_proxyclass_resources.
func (r *Reconciler) maybeCleanup(ctx context.Context, logger *zap.SugaredLogger, pc *tsapi.ProxyClass) error {
	ix := slices.Index(pc.Finalizers, reconciler.FinalizerName)
	if ix < 0 {
		logger.Debugf("no finalizer, nothing to do")
		r.mu.Lock()
		defer r.mu.Unlock()
		r.managedProxyClasses.Remove(pc.UID)
		gaugeProxyClassResources.Set(int64(r.managedProxyClasses.Len()))
		return nil
	}
	pc.Finalizers = append(pc.Finalizers[:ix], pc.Finalizers[ix+1:]...)
	if err := r.Update(ctx, pc); err != nil {
		return fmt.Errorf("failed to remove finalizer: %w", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.managedProxyClasses.Remove(pc.UID)
	gaugeProxyClassResources.Set(int64(r.managedProxyClasses.Len()))
	logger.Infof("ProxyClass resources have been cleaned up")
	return nil
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
		if crd.Name != ServiceMonitorCRD {
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

// getServicesNodePortRange attempts to determine the Service NodePort range for this cluster by
// creating a deliberately invalid Service with a NodePort that is too large and parsing the returned
// validation error. Returns nil if unable to determine port range.
// https://kubernetes.io/docs/concepts/services-networking/service/#type-nodeport
func getServicesNodePortRange(ctx context.Context, c client.Client, tsNamespace string, logger *zap.SugaredLogger) *tsapi.PortRange {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testSvcName,
			Namespace: tsNamespace,
			Labels: map[string]string{
				kubetypes.LabelManaged: "true",
			},
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeNodePort,
			Ports: []corev1.ServicePort{
				{
					Name:       testSvcName,
					Port:       8080,
					TargetPort: intstr.FromInt32(8080),
					Protocol:   corev1.ProtocolUDP,
					NodePort:   invalidSvcNodePort,
				},
			},
		},
	}

	// NOTE(ChaosInTheCRD): ideally this would be a server side dry-run but could not get it working
	err := c.Create(ctx, svc)
	if err == nil {
		return nil
	}

	if validPorts := getServicesNodePortRangeFromErr(err.Error()); validPorts != "" {
		pr, err := parseServicesNodePortRange(validPorts)
		if err != nil {
			logger.Debugf("failed to parse NodePort range set for Kubernetes Cluster: %w", err)
			return nil
		}

		return pr
	}

	return nil
}

func getServicesNodePortRangeFromErr(err string) string {
	reg := regexp.MustCompile(`\d{1,5}-\d{1,5}`)
	matches := reg.FindAllString(err, -1)
	if len(matches) != 1 {
		return ""
	}

	return matches[0]
}

// parseServicesNodePortRange converts the `ValidPorts` string field in the Kubernetes PortAllocator error and converts it to
// PortRange
func parseServicesNodePortRange(p string) (*tsapi.PortRange, error) {
	parts := strings.Split(p, "-")
	s, err := strconv.ParseUint(parts[0], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("failed to parse string as uint16: %w", err)
	}

	var e uint64
	switch len(parts) {
	case 1:
		e = s
	case 2:
		e, err = strconv.ParseUint(parts[1], 10, 16)
		if err != nil {
			return nil, fmt.Errorf("failed to parse string as uint16: %w", err)
		}
	default:
		return nil, fmt.Errorf("failed to parse port range %q", p)
	}

	portRange := &tsapi.PortRange{Port: uint16(s), EndPort: uint16(e)}
	if !portRange.IsValid() {
		return nil, fmt.Errorf("port range %q is not valid", portRange.String())
	}

	return portRange, nil
}

// validateNodePortRanges checks that the port range specified is valid. It also ensures that the specified ranges
// lie within the NodePort Service port range specified for the Kubernetes API Server.
func validateNodePortRanges(ctx context.Context, c client.Client, kubeRange *tsapi.PortRange, pc *tsapi.ProxyClass) error {
	if pc.Spec.StaticEndpoints == nil {
		return nil
	}

	portRanges := pc.Spec.StaticEndpoints.NodePort.Ports

	if kubeRange != nil {
		for _, pr := range portRanges {
			if !kubeRange.Contains(pr.Port) || (pr.EndPort != 0 && !kubeRange.Contains(pr.EndPort)) {
				return fmt.Errorf("range %q is not within Cluster configured range %q", pr.String(), kubeRange.String())
			}
		}
	}

	for _, r := range portRanges {
		if !r.IsValid() {
			return fmt.Errorf("port range %q is invalid", r.String())
		}
	}

	// TODO(ChaosInTheCRD): if a ProxyClass that made another invalid (due to port range clash) is deleted,
	// the invalid ProxyClass doesn't get reconciled on, and therefore will not go valid. We should fix this.
	proxyClassRanges, err := getPortsForProxyClasses(ctx, c)
	if err != nil {
		return fmt.Errorf("failed to get port ranges for ProxyClasses: %w", err)
	}

	for _, r := range portRanges {
		for pcName, pcr := range proxyClassRanges {
			if pcName == pc.Name {
				continue
			}
			if pcr.ClashesWith(r) {
				return fmt.Errorf("port ranges for ProxyClass %q clash with existing ProxyClass %q", pc.Name, pcName)
			}
		}
	}

	if len(portRanges) == 1 {
		return nil
	}

	sort.Slice(portRanges, func(i, j int) bool {
		return portRanges[i].Port < portRanges[j].Port
	})

	for i := 1; i < len(portRanges); i++ {
		prev := portRanges[i-1]
		curr := portRanges[i]
		if curr.Port <= prev.Port || curr.Port <= prev.EndPort {
			return fmt.Errorf("overlapping ranges: %q and %q", prev.String(), curr.String())
		}
	}

	return nil
}

// getPortsForProxyClasses gets the port ranges for all the other existing ProxyClasses
func getPortsForProxyClasses(ctx context.Context, c client.Client) (map[string]tsapi.PortRanges, error) {
	pcs := new(tsapi.ProxyClassList)

	err := c.List(ctx, pcs)
	if err != nil {
		return nil, fmt.Errorf("failed to list ProxyClasses: %w", err)
	}

	portRanges := make(map[string]tsapi.PortRanges)
	for _, i := range pcs.Items {
		if !tsoperator.ProxyClassIsReady(&i) {
			continue
		}
		if se := i.Spec.StaticEndpoints; se != nil && se.NodePort != nil {
			portRanges[i.Name] = se.NodePort.Ports
		}
	}

	return portRanges, nil
}
