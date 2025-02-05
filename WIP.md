This is a WIP implementation of supporting static endpoints for the operator's proxies.

To deploy you can either build from source or deploy using europe-west2-docker.pkg.dev/tailscale-sandbox/irbe-images/operator:v0.0.3staticep operator image and the CRDs (at least ProxyClass) from this branch.

i.e.

```
$ kubectl apply -f ./cmd/k8s-operator/deploy/crds
$ helm upgrade --install operator tailscale/tailscale-operator -n tailscale --set installCRDs=false --create-namespace  --set oauth.clientId=<OAuth client ID> --set oauth.clientSecret=<OAuth client secret> --set operatorConfig.logging=debug --set operatorConfig.image.repo=europe-west2-docker.pkg.dev/tailscale-sandbox/irbe-images/operator --set operatorConfig.image.tag=v0.0.3staticep
```

This change adds a new ability to set static endpoints on which the proxy can be reached.
This is experimentation towards ensuring direct connectivity in complex environments.

Some example static endpoints that could be set:
(I have not yet tested these solutions e2e)

1. Deploy in a cluster that has (some nodes) with public IPs, create a NodePort Service that exposes the proxy on the node's public IP address, pass the nodes' public IPs + NodePorts as static endpoints

Assuming that the nodes have public IPs 35.246.36.164, 35.246.83.1, example manifests to expose a Tailscale LoadBalancer Service could be like:

```
apiVersion: tailscale.com/v1alpha1
kind: ProxyClass
metadata:
  name: eps
spec:
  statefulSet:
    pod:
      labels:
        app:  ts-proxy
      tailscaleContainer:
        env:
        - name: PORT
          value: "1234"
  tailscale:
    endpoints:
      staticEndpoints:
      - 35.246.36.164:30333
      - 35.246.83.1:30333
---
apiVersion: v1
kind: Service
metadata:
  name: ts-proxy-np
  namespace: default
spec:
  ports:
  - nodePort: 30333
    port: 1234
    protocol: UDP
    targetPort: 1234
  selector:
    app: ts-proxy
  type: NodePort
---
apiVersion: v1
kind: Service
metadata:
  annotations:
    tailscale.com/hostname: kuard
  labels:
    tailscale.com/proxy-class: eps
    app: kuard
  name: kuard
  namespace: default
spec:
  ports:
  - port: 80
    protocol: TCP
    targetPort: 8080
  selector:
    app: kuard
  type: LoadBalancer
  loadBalancerClass: tailscale
```

2. Deploy an NLB and pass NLB IP:Port as the static endpoint.
For example, you could expose the proxy via a NodePort service, similarly to how it's done above, but on node's private IP and then point the load balancer at the node's endpoint.
(I have not tested this yet.)
