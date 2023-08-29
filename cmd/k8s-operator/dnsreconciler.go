// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// tailscale-operator provides a way to expose services running in a Kubernetes
// cluster to your Tailnet and expose Tailnet services to your cluster workloads.
package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/coredns/caddy/caddyfile"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const (
	defaultClusterDNSNamespace = "kube-system"

	kubeDNSStubDomainsKey = "stubDomains"

	coreDNSCorefileKey = "Corefile"
	tsNetKey           = "ts.net"
)

var (
	// If you add a new one here also update the operator's RBAC
	// TODO (irbekrm): make it possible for users to configure configmap
	// names/namespaces via an operator flag
	knownKubeDNSConfigMapNames = []string{"kube-dns"}
	// CoreDNS Helm chart generates this name depending on what name users
	// have given to CoreDNS release. By default this will be
	// 'coredns-coredns'
	// https://github.com/coredns/helm/blob/562d3c8809db9edbad89ae2006a4bd81c34b7b8f/charts/coredns/templates/configmap.yaml#L6
	knownCoreDNSConfigMapNames = []string{"coredns", "coredns-coredns"}
)

// dnsReconciler knows how to update common cluster DNS setups to add a stub ts.net
// nameserver
type dnsReconciler struct {
	client.Client
	operatorNamespace string
	logger            *zap.SugaredLogger
}

func (r *dnsReconciler) Reconcile(ctx context.Context, req reconcile.Request) (res reconcile.Result, err error) {
	res = reconcile.Result{}
	key := req.NamespacedName
	logger := r.logger.With("service", req.Name, req.Namespace)
	logger.Info("starting reconcile")
	defer logger.Info("finished reconcile")

	svc := &corev1.Service{}
	// get the ts.net nameserver service, check if it has cluster IP set
	err = r.Get(ctx, key, svc)
	if apierrors.IsNotFound(err) {
		logger.Info("nameserver Service not found, waiting...")
		return res, nil
	}
	if err != nil {
		logger.Errorf("error retrieving nameserver Service: %v", err)
		return res, err
	}
	if svc.Spec.ClusterIP == "" || svc.Spec.ClusterIP == "None" {
		logger.Info("namserver Service not yet ready, waiting...")
		return res, nil
	}

	tsNetNS := svc.Spec.ClusterIP

	// We don't have a reliable way how to determine what DNS the cluster is
	// actually using so we just try to find and modify kube-dns/CoreDNS
	// configs
	kubeDNSCM := &corev1.ConfigMap{}
	kubeDNSFound := false
	for _, cmName := range knownKubeDNSConfigMapNames {
		nsName := types.NamespacedName{Name: cmName, Namespace: defaultClusterDNSNamespace}
		err := r.Get(ctx, nsName, kubeDNSCM)
		if apierrors.IsNotFound(err) {
			logger.Debugf("looking for kube-dns config, configmap %s/%s not found", defaultClusterDNSNamespace, cmName)
			continue
		}
		if err != nil {
			logger.Errorf("error trying to retrieve kube-dns config: %v", err)
			return res, err
		}
		logger.Infof("kube-dns config found in configmap %s/%s", defaultClusterDNSNamespace, cmName)
		kubeDNSFound = true
		// presumably there will only ever be one
		break
	}
	// it is possible that both kube-dns and CoreDNS are deployed and we
	// don't have a reliable way to tell which one is used, so update both
	coreDNSCM := &corev1.ConfigMap{}
	coreDNSFound := false
	for _, cmName := range knownCoreDNSConfigMapNames {
		nsName := types.NamespacedName{Name: cmName, Namespace: defaultClusterDNSNamespace}
		err := r.Get(ctx, nsName, coreDNSCM)
		if apierrors.IsNotFound(err) {
			logger.Debugf("looking for coreDNS config, configmap %s/%s not found", defaultClusterDNSNamespace, cmName)
			continue
		}
		if err != nil {
			logger.Errorf("error trying to retrieve CoreDNS config: %v", err)
			return res, err
		}
		logger.Infof("CoreDNS config found in configmap %s/%s", defaultClusterDNSNamespace, cmName)
		coreDNSFound = true
		// presumably there will only ever be one
		break
	}

	if !kubeDNSFound && !coreDNSFound {
		logger.Info("neither kube-dns nor CoreDNS config was found. Users who want to use Tailscale egress will need to configure ts.net DNS manually")
		return res, nil
	}

	if kubeDNSFound {
		logger.Infof("ensuring that kube-dns config in ConfigMap %s/%s contains ts.net stub nameserver", defaultClusterDNSNamespace, kubeDNSCM.Name)

		stubDomains := make(map[string][]string)
		if kubeDNSCM.Data == nil {
			kubeDNSCM.Data = make(map[string]string)
		}
		if _, ok := kubeDNSCM.Data[kubeDNSStubDomainsKey]; ok {
			err = json.Unmarshal([]byte(kubeDNSCM.Data[kubeDNSStubDomainsKey]), &stubDomains)
			if err != nil {
				logger.Errorf("error unmarshalling kube-dns config: %v", err)
				return res, err
			}
		}
		if _, ok := stubDomains[tsNetKey]; !ok {
			stubDomains[tsNetKey] = make([]string, 1)
		}
		if stubDomains[tsNetKey][0] != tsNetNS {
			stubDomains[tsNetKey][0] = tsNetNS
			stubDomainsBytes, err := json.Marshal(stubDomains)
			if err != nil {
				logger.Errorf("error marshaling stub domains: %v", err)
				return res, err
			}
			(*kubeDNSCM).Data[kubeDNSStubDomainsKey] = string(stubDomainsBytes)
			if err := r.Update(ctx, kubeDNSCM); err != nil {
				logger.Errorf("error updating kube-dns config: %v", err)
				return res, err
			}
			logger.Infof("kube-dns config in ConfigMap %s/%s updated with ts.net stubserver at %s", defaultClusterDNSNamespace, kubeDNSCM.Name, svc.Spec.ClusterIP)
		} else {
			logger.Debugf("kube-dns config in ConfigMap %s/%s already up to date with ts.net stubserver at %s", defaultClusterDNSNamespace, kubeDNSCM.Name, svc.Spec.ClusterIP)
		}
	}

	if coreDNSFound {
		// coreDNS does not appear to have defaults where it doesn't need Corefile to
		// contain some configuration, so if this is unset something is off and we don't
		// know what to do
		if _, ok := coreDNSCM.Data[coreDNSCorefileKey]; !ok {
			logger.Infof("found what appears to be a core-dns config in ConfigMap %s/%s, but it does not contain a Corefile, do nothing", defaultClusterDNSNamespace, coreDNSCM.Name)
			return res, nil
		}
		corefileBytes := []byte(coreDNSCM.Data[coreDNSCorefileKey])
		// do things to unmarshal Corefile and update it if needed
		b, err := caddyfile.ToJSON(corefileBytes)
		if err != nil {
			logger.Errorf("error converting Caddyfile to JSON: %v", err)
			return res, err
		}

		cf := &caddyfile.EncodedCaddyfile{}
		err = json.Unmarshal(b, cf)
		if err != nil {
			logger.Errorf("error unmarshalling Caddyfile: %v", err)
			return res, err
		}

		foundTSNetDirective := false
		needsUpdate := false
		for i, serverBlock := range *cf {
			// We are looking for a server block that has a single key 'ts.net'
			if (len(serverBlock.Keys) != 1) || serverBlock.Keys[0] != tsNetKey {
				continue
			}
			foundTSNetDirective = true

			// check if forward directive needs updating
			currentNs, err := nsFromForwardDirective(serverBlock.Body)
			if err != nil {
				logger.Errorf("error retrieving current ts.net namserver from Corefile forward directive: %v", err)
				return res, err
			}
			if tsNetNS != currentNs {
				newForwardDirective := forwardDirectiveForNS(tsNetNS)
				serverBlock.Body = newForwardDirective
				(*cf)[i] = serverBlock
				needsUpdate = true
				logger.Infof("updated forward directive in ts.net serverblock for Corefile: %+#v", newForwardDirective)
			}
			break
		}
		if !foundTSNetDirective {
			tsNetServerBlock := serverBlockForNS(tsNetNS)
			(*cf) = append((*cf), tsNetServerBlock)
			needsUpdate = true
			logger.Infof("adding a new ts.net server block to Corefile: %+#v", tsNetServerBlock)
		}

		if needsUpdate {
			cfBytes, err := json.Marshal(cf)
			if err != nil {
				logger.Errorf("error marshalling updated CoreDNS config: %v", err)
				return res, err
			}
			// updated Caddyfile
			updatedCF, err := caddyfile.FromJSON(cfBytes)
			if err != nil {
				logger.Errorf("error converting updated CoreDNS config to Corefile: %v", err)
				return res, err
			}
			// TODO (irbekrm): can we somehow validate that this is a valid Corefile?
			coreDNSCM.Data[coreDNSCorefileKey] = string(updatedCF)

			// TODO (irbekrm): should probably SSA here
			err = r.Update(ctx, coreDNSCM)
			if err != nil {
				logger.Errorf("error updating CoreDNS configmap: %v", err)
				return res, err
			}
		}

	}

	return res, nil
}

func forwardDirectiveForNS(ip string) [][]interface{} {
	return [][]interface{}{{"forward", ".", ip}}
}

func serverBlockForNS(ip string) caddyfile.EncodedServerBlock {
	directive := forwardDirectiveForNS(ip)
	return caddyfile.EncodedServerBlock{
		Keys: []string{tsNetKey},
		Body: directive,
	}
}

func nsFromForwardDirective(directive [][]interface{}) (ip string, _ error) {
	// this is a directive created by forwardDirectiveForNS func and
	// shouldn't have been modified by anyone
	if len(directive) != 1 {
		return "", fmt.Errorf("unexpected length of ts.net forward directive, expected 1 got %d", len(directive))
	}

	statement := directive[0]

	if len(statement) != 3 {
		return "", fmt.Errorf("unexpected ts.net forward statement %v, expected 3 elements, got %d", statement, len(statement))
	}
	ip, ok := statement[2].(string)
	if !ok {
		return "", fmt.Errorf("cannot convert %v to string", statement[2])
	}
	return ip, nil
}
