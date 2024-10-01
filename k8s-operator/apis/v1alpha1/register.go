// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package v1alpha1

import (
	"fmt"

	"tailscale.com/k8s-operator/apis"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
)

// SchemeGroupVersion is group version used to register these objects
var SchemeGroupVersion = schema.GroupVersion{Group: apis.GroupName, Version: "v1alpha1"}

// Resource takes an unqualified resource and returns a Group qualified GroupResource
func Resource(resource string) schema.GroupResource {
	return SchemeGroupVersion.WithResource(resource).GroupResource()
}

var (
	SchemeBuilder      runtime.SchemeBuilder
	localSchemeBuilder = &SchemeBuilder
	AddToScheme        = localSchemeBuilder.AddToScheme

	GlobalScheme *runtime.Scheme
)

func init() {
	// We only register manually written functions here. The registration of the
	// generated functions takes place in the generated files. The separation
	// makes the code compile even when the generated files are missing.
	localSchemeBuilder.Register(addKnownTypes)

	GlobalScheme = runtime.NewScheme()
	if err := scheme.AddToScheme(GlobalScheme); err != nil {
		panic(fmt.Sprintf("failed to add k8s.io scheme: %s", err))
	}
	if err := AddToScheme(GlobalScheme); err != nil {
		panic(fmt.Sprintf("failed to add tailscale.com scheme: %s", err))
	}
}

// Adds the list of known types to api.Scheme.
func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(SchemeGroupVersion,
		&Connector{},
		&ConnectorList{},
		&ProxyClass{},
		&ProxyClassList{},
		&DNSConfig{},
		&DNSConfigList{},
		&Recorder{},
		&RecorderList{},
		&ProxyGroup{},
		&ProxyGroupList{},
	)

	metav1.AddToGroupVersion(scheme, SchemeGroupVersion)
	return nil
}
