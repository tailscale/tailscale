# HA failover

This is an experimental prototype for fast failover for subnet routers via Kubernetes operator.

Problem: how can we ensure that if multiple subnet router replicas are ran and a replica is about to be deleted (i.e StatefulSet upgrade), peers that currently route via this subnet router will switch to another subnet router instance _before_ the first one is deleted.

This code change:

- adds a lameduck local API endpoint that can be called to shut down control client and thus force control to consider this node inactive 

- adds a prestop hook definition to Connector StatefulSet that calls terminate endpoint

- bumps termination grace period seconds on Connector Pod spec 30s -> 120s to ensure that the /terminate endpoint gets a chance to finish

This change also includes WIP work to run Connector in multi-replica mode.

### How to try it:

```
$ helm upgrade --install operator tailscale-dev/tailscale-operator -n tailscale --create-namespace --set operatorConfig.image.repo=gcr.io/csi-test-290908/operator --set operatorConfig.image.tag=0.12connmultir --set proxyConfig.image.repo=gcr.io/csi-test-290908/proxy --set proxyConfig.image.tag=v0.0.15connmultir  -n tailscale --create-namespace  --set oauth.clientId=<id> --set oauth.clientSecret=<>
```

```
$ kubectl delete crd connectors.tailscale.com // need to re-apply CRD from this branch
```

(from this branch)

```
$ kubectl apply -f cmd/k8s-operator/deploy/crds/tailscale.com_connectors.yaml
```

Apply a multi-replica Connector with some route:

```
apiVersion: tailscale.com/v1alpha1
kind: Connector
metadata:
  name: prod
spec:
  tags:
  - "tag:prod"
  hostname: ts-prod
  subnetRouter:
  - <route>
  replicas: 3
```

Test failover during deletion, i.e curl the backend in a tight-ish loop and delete the primary Pod, you should be able to observe that within ~a minute traffic switches over to the second Pod, meanwhile the connection should keep working without an obvious hitch.
(I was curl-ing with 1s interval and saw a RST, then it switched over)


