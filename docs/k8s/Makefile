# Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

ifndef IMAGE_TAG
  $(error "IMAGE_TAG is not set")
endif

ROUTES ?= ""
SA_NAME ?= tailscale
KUBE_SECRET ?= tailscale

build:
	@docker build . -t $(IMAGE_TAG)

push: build
	@docker push $(IMAGE_TAG)

rbac:
	@sed -e "s;{{KUBE_SECRET}};$(KUBE_SECRET);g" role.yaml | kubectl apply -f -
	@sed -e "s;{{SA_NAME}};$(SA_NAME);g" rolebinding.yaml | kubectl apply -f -
	@sed -e "s;{{SA_NAME}};$(SA_NAME);g" sa.yaml | kubectl apply -f -

sidecar:
	@kubectl delete -f sidecar.yaml --ignore-not-found --grace-period=0
	@sed -e "s;{{KUBE_SECRET}};$(KUBE_SECRET);g" sidecar.yaml | sed -e "s;{{SA_NAME}};$(SA_NAME);g" | sed -e "s;{{IMAGE_TAG}};$(IMAGE_TAG);g" | kubectl create -f-

userspace-sidecar:
	@kubectl delete -f userspace-sidecar.yaml --ignore-not-found --grace-period=0
	@sed -e "s;{{KUBE_SECRET}};$(KUBE_SECRET);g" userspace-sidecar.yaml | sed -e "s;{{SA_NAME}};$(SA_NAME);g" | sed -e "s;{{IMAGE_TAG}};$(IMAGE_TAG);g" | kubectl create -f-

proxy:
	@kubectl delete -f proxy.yaml --ignore-not-found --grace-period=0
	@sed -e "s;{{KUBE_SECRET}};$(KUBE_SECRET);g" proxy.yaml | sed -e "s;{{SA_NAME}};$(SA_NAME);g" | sed -e "s;{{IMAGE_TAG}};$(IMAGE_TAG);g" | sed -e "s;{{DEST_IP}};$(DEST_IP);g" | kubectl create -f-

subnet-router:
	@kubectl delete -f subnet.yaml --ignore-not-found --grace-period=0
	@sed -e "s;{{KUBE_SECRET}};$(KUBE_SECRET);g" subnet.yaml | sed -e "s;{{SA_NAME}};$(SA_NAME);g" | sed -e "s;{{IMAGE_TAG}};$(IMAGE_TAG);g" | sed -e "s;{{ROUTES}};$(ROUTES);g" | kubectl create -f-
