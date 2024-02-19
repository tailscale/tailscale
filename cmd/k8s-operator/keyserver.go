// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"go.uber.org/zap"
	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"tailscale.com/client/tailscale"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
)

type keyServer struct {
	restConfig *rest.Config
	client.Client
	logger            *zap.SugaredLogger
	tsNamespace       string
	defaultDeviceTags []string
	tsClient          tsClient
}

func (ks *keyServer) runKeyServer() error {
	proxyServiceAccountName := fmt.Sprintf("system:serviceaccount:%s:proxies", ks.tsNamespace)
	// create a client-go client as c/r client cannot be used to directly
	// access Auth interface to create TokenReviews. TokenReviews are not
	// objects that exist in cluster, so the normal c/r flow of 'CREATE and
	// object, if needed to observe its current state GET it does not work
	// here- we need to read the status from the TokenReview status as
	// returned in response, so we need to use the actual auth client.
	// TODO: maybe I actually don't need to do this because the object
	// passed to c/r Create would get updated?
	kubeClient, err := kubernetes.NewForConfig(ks.restConfig)
	if err != nil {
		return fmt.Errorf("error creating a new kube client: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		ks.logger.Debugf("received request for an auth key")
		// Get the auth token - like https://github.com/kubernetes/apiserver/blob/release-1.29/pkg/authentication/request/bearertoken/bearertoken.go#L42-L63
		auth := strings.TrimSpace(r.Header.Get("Authorization"))
		if auth == "" {
			ks.logger.Info("received a request with no auth header")
			http.Error(w, "permission denied", http.StatusForbidden)
			return
		}
		parts := strings.SplitN(auth, " ", 3)
		if len(parts) < 2 || strings.ToLower(parts[0]) != "bearer" {
			ks.logger.Info("received a request with no bearer token")
			http.Error(w, "permission denied", http.StatusForbidden)
			return
		}

		token := parts[1]

		// Empty bearer tokens aren't valid
		if len(token) == 0 {
			ks.logger.Info("received a request with an empty bearer token")
			http.Error(w, "permission denied", http.StatusForbidden)
			return
		}
		// create a TokenReview
		tr := &authv1.TokenReview{
			Spec: authv1.TokenReviewSpec{Token: token, Audiences: []string{"ts-keyserver"}},
		}

		// TODO: alt would be to delegate via auth webhook - that's how
		// RBAC proxy does it. Compare.
		resp, err := kubeClient.AuthenticationV1().TokenReviews().Create(r.Context(), tr, metav1.CreateOptions{})
		if err != nil {
			ks.logger.Errorf("error creating a TokenReview: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		if !resp.Status.Authenticated {
			ks.logger.Info("token was not authenticated")
			http.Error(w, "permission denied", http.StatusForbidden)
			return
		}
		// TODO: set and validate audience
		// We know that only ServiceAccount 'proxies' in operator
		// namespace should be allowed to call 'keys' endpoint.
		// Alternatively we could assign 'proxies' an RBAC allowing it
		// to call '/keys' endpoint (RBAC for non-resource URLs). At the
		// moment I don't see a value in doing that as we know what
		// ServiceAccount is allowed to perform the action and an
		// operator installation always includes this ServiceAccount.
		if username := resp.Status.User.Username; username != proxyServiceAccountName {
			ks.logger.Info("received a request for token for user %s, expected %s", username, proxyServiceAccountName)
			http.Error(w, "permission denied", http.StatusForbidden)
			return
		}
		// TODO: ensure that this will always have extras when the token is sent from containerboot
		if resp.Status.User.Extra == nil {
			ks.logger.Info("received a request for a token that does not contain extra information, please report this")
			http.Error(w, "unable to identify caller Pod", http.StatusForbidden)
			return
		}
		if len(resp.Status.User.Extra[serviceaccount.PodNameKey]) != 1 || resp.Status.User.Extra[serviceaccount.PodNameKey][0] == "" {
			ks.logger.Infof("impossible to identify caller Pod from token review response: %#+v", resp.Status.User.Extra[serviceaccount.PodNameKey])
			http.Error(w, "unable to identify caller Pod", http.StatusForbidden)
			return
		}
		podName := types.NamespacedName{Namespace: ks.tsNamespace, Name: resp.Status.User.Extra[serviceaccount.PodNameKey][0]}
		ks.logger.Debugf("request for key authenticated as from Pod %s", podName)

		// TODO: cache metadata only for these, filter ts namespace and labels
		pod := &corev1.Pod{}
		// TODO: is it right to use this context?
		if err := ks.Client.Get(r.Context(), podName, pod); err != nil {
			ks.logger.Errorf("unable to retrieve caller Pod from cache: %v", err)
			http.Error(w, "unable to identify caller Pod", http.StatusForbidden)
			return
		}
		// Get the parent resource and figure out what tags are needed.
		// Alternatives could be 1) annotate Pods with the desired ACL
		// tags 2) pass each StatefulSet a specific URL that includes
		// the tags (i.e base64 encoded). But 2) would probably require
		// RBAC for calling _that_ URL (and we currently use the same
		// ServiceAccount for all proxies). 1) could be ok (and would
		// also solve the problem where user updating ACL tags is not
		// picked up by proxies), but should discuss the model
		// (including what should happen when ACL tags are updated).
		// Generally of course should speed this up much as possible.
		tags, err := ks.tagsForPod(r.Context(), pod)
		if err != nil {
			ks.logger.Errorf("error determining ACL tags to apply to the auth key: %v", err)
			http.Error(w, "error determining ACL tags", http.StatusInternalServerError)
			return
		}
		// create the device
		// TODO: bump a metric here. probably should also be user facing?
		key, err := ks.newAuthKey(r.Context(), tags)
		if err != nil {
			ks.logger.Errorf("error determining ACL tags to apply to the auth key")
			http.Error(w, "error creating a new auth key", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(200)
		// probably?
		w.Header().Set("Content-Type", "text/plain;charset=UTF-8")
		w.Write([]byte(key))
	})
	srv := http.Server{
		Handler: mux,
		Addr:    ":8443", // 443 is auth proxy if that's too running on this operator instance
	}
	ks.logger.Infof("running key server on %v", srv.Addr)
	return srv.ListenAndServe()
}

func (ks *keyServer) newAuthKey(ctx context.Context, tags []string) (string, error) {
	caps := tailscale.KeyCapabilities{
		Devices: tailscale.KeyDeviceCapabilities{
			Create: tailscale.KeyDeviceCreateCapabilities{
				Reusable:      false,
				Preauthorized: true,
				Tags:          tags,
			},
		},
	}
	key, _, err := ks.tsClient.CreateKey(ctx, caps)
	if err != nil {
		return "", err
	}
	return key, nil
}

func (ks *keyServer) tagsForPod(ctx context.Context, pod *corev1.Pod) ([]string, error) {
	parentLabels, err := managedLabelsFromPod(pod)
	if err != nil {
		return nil, fmt.Errorf("error determining parent resource labels: %v", err)
	}
	tags, err := ks.aclTagsForResource(ctx, parentLabels)
	if err != nil {
		return nil, fmt.Errorf("error determining ACl tags: %v", err)
	}
	return tags, nil
}

func (ks *keyServer) aclTagsForResource(ctx context.Context, labels map[string]string) ([]string, error) {
	switch labels[LabelParentType] {
	case "svc":
		svcName := types.NamespacedName{Namespace: labels[LabelParentNamespace], Name: labels[LabelParentName]}
		svc := &corev1.Service{}
		if err := ks.Get(ctx, svcName, svc); err != nil {
			return nil, fmt.Errorf("error getting Service: %v", err)
		}
		return ks.aclsForObjectAnnotations(svc.Annotations), nil
	case "ingress":
		ingName := types.NamespacedName{Namespace: labels[LabelParentNamespace], Name: labels[LabelParentName]}
		ing := &networkingv1.Ingress{}
		if err := ks.Get(ctx, ingName, ing); err != nil {
			return nil, fmt.Errorf("error getting Ingress: %v", err)
		}
		return ks.aclsForObjectAnnotations(ing.Annotations), nil
	case "connector":
		connectorName := types.NamespacedName{Name: labels[LabelParentName]}
		conn := &tsapi.Connector{}
		if err := ks.Get(ctx, connectorName, conn); err != nil {
			return nil, fmt.Errorf("error getting Connector: %v", err)
		}
		if len(conn.Spec.Tags) > 0 {
			return conn.Spec.Tags.Stringify(), nil
		}
		return ks.defaultDeviceTags, nil
	default:
		return nil, fmt.Errorf("unkown parent type: %s", labels[LabelParentType])
	}
}

func (ks *keyServer) aclsForObjectAnnotations(annots map[string]string) []string {
	if annots == nil || annots[AnnotationTags] == "" {
		return ks.defaultDeviceTags
	}
	return strings.Split(annots[AnnotationTags], ",")
}

func managedLabelsFromPod(pod *corev1.Pod) (map[string]string, error) {
	labels := make(map[string]string)
	for _, labelName := range []string{LabelManaged, LabelParentName, LabelParentNamespace, LabelParentType} {
		if labelVal := pod.GetLabels()[labelName]; labelVal == "" {
			return nil, fmt.Errorf("Pod does not have label: %s", labelName)
		} else {
			labels[labelName] = labelVal
		}
	}
	return labels, nil
}
