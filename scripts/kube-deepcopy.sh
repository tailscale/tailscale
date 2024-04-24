#!/usr/bin/env sh

set -eu

./tool/go run  sigs.k8s.io/controller-tools/cmd/controller-gen 	object:headerFile=./header.txt paths=./k8s-operator/apis/...

# At the moment controller-gen does not support adding custom tags to generated
# files. We want to exclude all kube-related code from plan9 builds because some
# apimachinery libraries refer to syscalls that are not available for plan9
# https://github.com/kubernetes/apimachinery/blob/v0.28.2/pkg/util/net/util.go#L42-L63 
sed -i.bak "1 s|$| \\&\\& \\!plan9|" k8s-operator/apis/v1alpha1/zz_generated.deepcopy.go && rm k8s-operator/apis/v1alpha1/zz_generated.deepcopy.go.bak
