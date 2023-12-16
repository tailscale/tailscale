#!/usr/bin/env sh

set -eu

./tool/go run  sigs.k8s.io/controller-tools/cmd/controller-gen 	object:headerFile=./header.txt paths=./k8s-operator/apis/...
