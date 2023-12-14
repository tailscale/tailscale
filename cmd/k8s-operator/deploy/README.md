# Tailscale Kubernetes operator deployment manifests

./cmd/k8s-operator/deploy contain various Tailscale Kubernetes operator deployment manifests.

## Helm chart

`./cmd/k8s-operator/deploy/chart` contains Tailscale operator Helm chart templates.
The chart templates are also used to generate the static manifest, so developers must ensure that any changes applied to the chart have been propagated to the static manifest by running `go generate tailscale.com/cmd/k8s-operator`

## Static manifests

`./cmd/k8s-operator/deploy/manifests/operator.yaml` is a static manifest for the operator generated from the Helm chart templates for the operator.