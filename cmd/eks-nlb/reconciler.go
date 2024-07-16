package main

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	elb "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"tailscale.com/types/ptr"
)

const (
	eksNLBConfigAnnotation = "tailscale.com/eksnlb-configmap"
	pretendpointEnvVar     = "TS_DEBUG_PRETENDPOINT"

	wireguardPort int32  = 41641
	metricsPort   string = "9001"
)

type podReconciler struct {
	client.Client
	logger *zap.SugaredLogger
}

type podConfig struct {
	portFromEnv    int32
	lbAddrsFromEnv []string
	lbARN          string
	vpcID          string
	podLabels      map[string]string
	backendIP      string // Pod IP
}

func (pr *podReconciler) Reconcile(ctx context.Context, req reconcile.Request) (res reconcile.Result, err error) {
	logger := pr.logger.With("pod-ns", req.Namespace, "pod-name", req.Name)
	logger.Debugf("starting reconcile")
	defer logger.Debugf("reconcile finished")

	pod := new(corev1.Pod)
	err = pr.Get(ctx, req.NamespacedName, pod)
	if apierrors.IsNotFound(err) {
		logger.Debugf("Pod not found, assuming it was deleted")
		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to get Pod: %w", err)
	}

	if !pod.DeletionTimestamp.IsZero() {
		logger.Debugf("Pod is being deleted; currently doing nothing")
		// TODO: clean up load balancer resources
		return reconcile.Result{}, nil
	}

	if pod.Annotations[eksNLBConfigAnnotation] == "" {
		logger.Debugf("Pod does not have %s annotation, do nothing", eksNLBConfigAnnotation)
		return res, nil
		// TODO: clean up if removed
	}

	// TODO: validate Pod config

	// TODO: add a finalizer

	// Parse Pod config
	pc, err := pr.parseClusterConfig(ctx, pod)
	if err != nil {
		return res, fmt.Errorf("error parsing Pod config: %w", err)
	}
	if pc.backendIP == "" {
		logger.Info("[unexpected] Pod does not have an IP address allocated, waiting...")
		return res, nil
	}

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return res, fmt.Errorf("unable to load SDK config, %v", err)
	}
	cl := elb.NewFromConfig(cfg)

	resourceName := fmt.Sprintf("%s-%s", pod.Name, pod.Namespace)

	tgci := elb.CreateTargetGroupInput{
		VpcId:               &pc.vpcID,
		Name:                &resourceName,
		HealthCheckEnabled:  ptr.To(true), // TODO: internal pointer
		HealthCheckPort:     ptr.To(metricsPort),
		HealthCheckProtocol: "TCP",
		// TODO: other health check params
		// IpAddressType:  "ipv4", // TODO: determine from Pod IP
		Port:       ptr.To(wireguardPort),
		Protocol:   "UDP",
		TargetType: elbtypes.TargetTypeEnumIp,
	}
	// CreateTargetGroup is idempotent
	tgco, err := cl.CreateTargetGroup(ctx, &tgci)
	if err != nil {
		return res, fmt.Errorf("error creating target group %q", err)
	}
	if len(tgco.TargetGroups) == 0 {
		logger.Debugf("No target groups found after creation, waiting...")
		return res, nil
	}
	// Loop over and look up matching IP addresses
	var tg *elbtypes.TargetGroup
	for _, maybeTG := range tgco.TargetGroups {
		if strings.EqualFold(*maybeTG.TargetGroupName, resourceName) {
			logger.Debugf("found target group %s", resourceName)
			tg = &maybeTG
			// TODO: verify ports etc
		}
	}
	if tg == nil {
		logger.Infof("[unexpected] target group not found")
		return res, nil
	}

	if tg.TargetGroupArn == nil {
		logger.Infof("[unexpected] target group %+#v has no ARN", tg)
		return res, nil
	}
	logger.Debugf("found target group %v", tg.TargetGroupArn)

	// List targets
	hi := elb.DescribeTargetHealthInput{TargetGroupArn: tg.TargetGroupArn}
	ho, err := cl.DescribeTargetHealth(ctx, &hi)
	if err != nil {
		return res, fmt.Errorf("error describing target health: %w", err)
	}
	var targetExists bool
	for _, health := range ho.TargetHealthDescriptions {
		if health.Target.Id == &pc.backendIP {
			logger.Debugf("Target found %#+v", health.Target)
			targetExists = true
		} else {
			// TODO: Deregister the target
			logger.Debugf("Found target that should be deregistered: %#+v", health.Target)
		}
	}
	if !targetExists {
		logger.Debugf("target for %v does not exist, creating...", pc.backendIP)
		target := elb.RegisterTargetsInput{TargetGroupArn: tg.TargetGroupArn, Targets: []elbtypes.TargetDescription{
			{Id: ptr.To(pc.backendIP), Port: ptr.To(wireguardPort)},
		}}
		_, err := cl.RegisterTargets(ctx, &target)
		if err != nil {
			return res, fmt.Errorf("error registering target: %w", err)
		}
	}

	li := elb.DescribeListenersInput{LoadBalancerArn: &pc.lbARN}
	lo, err := cl.DescribeListeners(ctx, &li)
	if err != nil {
		return res, fmt.Errorf("error listing listeners: %w", err)
	}
	var lis *elbtypes.Listener
	port := pc.portFromEnv
	if port != 0 {
		for _, l := range lo.Listeners {
			if l.Port == &pc.portFromEnv {
				logger.Debugf("found existing listener on port %q", pc.portFromEnv)
				lis = &l
			}
		}
	} else {
		// figure out a free port
		searchFreePort := true
		for searchFreePort {
			suggestPort := int32(rand.Intn(65535)) // 1 - 65335
			found := false
			for _, l := range lo.Listeners {
				if l.Port == &suggestPort {
					found = true
					break
				}
			}
			if !found {
				port = suggestPort
				searchFreePort = false
			}
		}
		if port == 0 {
			return res, fmt.Errorf("unable to find a free port to expose on the listener: %w", err)
		}
	}
	for _, maybeLB := range lo.Listeners {
		if maybeLB.Port == ptr.To(port) {
			logger.Debugf("Found listener for port %v", port)
			lis = &maybeLB
			break
		}
	}

	if lis == nil {
		logger.Infof("listener for port %v not found, creating", port)
		lci := elb.CreateListenerInput{
			LoadBalancerArn: &pc.lbARN,
			Port:            ptr.To(port),
			Protocol:        "UDP",
			DefaultActions: []elbtypes.Action{
				{TargetGroupArn: tg.TargetGroupArn, Type: elbtypes.ActionTypeEnumForward},
			},
		}
		lco, err := cl.CreateListener(ctx, &lci)
		if err != nil {
			return res, fmt.Errorf("error creating listener: %w", err)
		}
		logger.Infof("created listener with arn: %v", lco.Listeners[0].ListenerArn)
	}

	dli := elb.DescribeLoadBalancersInput{LoadBalancerArns: []string{pc.lbARN}}
	dlo, err := cl.DescribeLoadBalancers(ctx, &dli)
	if len(dlo.LoadBalancers) != 1 {
		return res, fmt.Errorf("expected exactly 1 NLB with ARN %s, got %d", pc.lbARN, len(dlo.LoadBalancers))
	}
	lb := dlo.LoadBalancers[0]
	addrs := make([]string, 0)
	for _, z := range lb.AvailabilityZones {
		for _, a := range z.LoadBalancerAddresses {
			addrs = append(addrs, *a.IpAddress) // IPv6?
		}
	}
	if err := pr.ensurePretendPointUpToDate(ctx, pod, port, addrs); err != nil {
		return res, fmt.Errorf("error ensuring TS_DEBUG_PRETENDPOINT value is up to date: %w", err)
	}
	return reconcile.Result{}, nil
}

func (pr *podReconciler) ensurePretendPointUpToDate(ctx context.Context, p *corev1.Pod, port int32, addrs []string) error {
	var cont *corev1.Container
	for _, c := range p.Spec.Containers {
		if c.Name == "tailscale" {
			cont = &c
			break
		}
	}
	if cont == nil {
		return errors.New("pod does not have a 'tailscale' container")
	}

	// calculate value
	addrPorts := make([]string, 0)

	for _, a := range addrs {
		addrPorts = append(addrPorts, strings.Join([]string{a, string(port)}, ","))
	}
	pretendpoint := strings.Join(addrPorts, ",")

	for _, envVar := range cont.Env {
		if envVar.Name == pretendpointEnvVar {
			if envVar.Value != "" {
				// TODO: log an error out if this is not up to date
				pr.logger.Infof("env var set, do nothing")
				return nil
			} else if cmConfig := envVar.ValueFrom.ConfigMapKeyRef; cmConfig != nil {
				cm := &corev1.ConfigMap{}
				n := types.NamespacedName{Name: cmConfig.Name, Namespace: p.Namespace}
				err := pr.Get(ctx, n, cm)
				if err != nil && !apierrors.IsNotFound(err) {
					return fmt.Errorf("error retrieving ConfigMap: %w", err)
				}
				if apierrors.IsNotFound(err) {
					pr.logger.Infof("Creating ConfigMap")
					cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: cmConfig.Name},
						Data: map[string]string{cmConfig.Key: pretendpoint}}
					return pr.Create(ctx, cm)

				}
				if cm.Data[cmConfig.Key] != pretendpoint {
					pr.logger.Infof("Updating ConfigMap with wireguard endpoints value: %v", pretendpoint)
					cm.Data[cmConfig.Key] = pretendpoint
					return pr.Update(ctx, cm)
				}
			}
		}
	}
	return nil
}

func (pr *podReconciler) parseClusterConfig(ctx context.Context, p *corev1.Pod) (*podConfig, error) {

	var cont *corev1.Container
	for _, c := range p.Spec.Containers {
		if c.Name == "tailscale" {
			cont = &c
			break
		}
	}
	if cont == nil {
		return nil, errors.New("pod does not have a 'tailscale' container")
	}
	var pretendpoint string
	for _, envVar := range cont.Env {
		if envVar.Name == pretendpointEnvVar {
			if envVar.Value != "" {
				pretendpoint = envVar.Value
			} else if cmConfig := envVar.ValueFrom.ConfigMapKeyRef; cmConfig != nil {
				// Get the configmap
				// Read the value if exists
				cm := &corev1.ConfigMap{}
				n := types.NamespacedName{Name: cmConfig.Name, Namespace: p.Namespace}
				err := pr.Get(ctx, n, cm)
				if apierrors.IsNotFound(err) {
					pr.logger.Info("ConfigMap %s does not exist, it will be created")
				} else if err != nil {
					return nil, fmt.Errorf("error retrieving ConfigMap: %w", err)
				} else if cm.Data[cmConfig.Key] != "" {
					pretendpoint = cm.Data[cmConfig.Key]
					pr.logger.Infof("read wireguard endoints for ConfigMap: %v", pretendpoint)
				}
			}
			break
		}
	}
	if pretendpoint == "" {
		return nil, nil
	}
	addrs := strings.Split(pretendpoint, ",")

	var maybePort string
	var lbAddrs []string
	for _, a := range addrs {
		h, port, err := net.SplitHostPort(a)
		if err != nil {
			return nil, fmt.Errorf("error splitting host port: %v", err)
		}
		// if the ports are not the same, there is probably some issue, recreate the listener
		if maybePort != "" && maybePort != port {
			return nil, nil
		}
		maybePort = port
		lbAddrs = append(lbAddrs, h)
	}
	port, err := strconv.ParseInt(maybePort, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("error parsing port %q as int: %w", maybePort, err)
	}

	cm := &corev1.ConfigMap{}
	if err := pr.Get(ctx, types.NamespacedName{Namespace: p.Namespace, Name: p.Annotations[eksNLBConfigAnnotation]}, cm); err != nil {
		return nil, fmt.Errorf("ConfigMap %s not found", eksNLBConfigAnnotation)
	}
	vpcID := cm.Data["vpc_id"]
	if vpcID == "" {
		return nil, fmt.Errorf("vpc_id field not set for %s ConfigMap", eksNLBConfigAnnotation)
	}
	lbARN := cm.Data["lb_arn"]
	if lbARN == "" {
		return nil, fmt.Errorf("lb_arn not set for %s ConfigMap", eksNLBConfigAnnotation)
	}

	return &podConfig{
		portFromEnv:    int32(port),
		lbAddrsFromEnv: lbAddrs,
		vpcID:          vpcID,
		lbARN:          lbARN,
		podLabels:      p.Labels,
		backendIP:      p.Status.PodIP,
	}, nil
}
