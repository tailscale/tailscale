# This is a Kubernetes Operator egress HA prototype based on portmapping

It contains:
- containerboot/netfilter runner changes to parse egress services config and set up portmapping based DNAT
- two new operator reconcile loops to parse HA egress resources
- static manifests that imitate having a ProxyGroup deployed to cluster
- some other changes, additional RBAC etc

## To try this out

### Setup

(The setup steps use images built from this branch available from a public GCR that I own)

- set up a cluster WITHOUT the operator

From this branch:
- `$ kubectl apply -f cmd/k8s-operator/crds`
- install operator:
```
$ helm upgrade --install operator ./cmd/k8s-operator/deploy/chart/ --set operatorConfig.image.repo=gcr.io/csi-test-290908/operator --set operatorConfig.image.tag=v0.0.14egresshapm  -n tailscale --set oauth.clientId=<oauth-client-id> --set oauth.clientSecret=<oauth-client-secret>  --set operatorConfig.logging=debug --create-namespace --set operatorConfig.image.pullPolicy=IfNotPresent
```
- apply static manifests that imitate having a ProxyGroup:

Create a REUSABLE Tailscale auth key and update ./cmd/k8s-operator/egress-ha.yaml with it.

Run:

```
$ kubectl apply -f ./cmd/k8s-operator/egress-ha.yaml
```
- observe that the 'proxy group' `Pods` have come up:
```
$ kubectl get pods -n tailscale
NAME                       READY   STATUS    RESTARTS   AGE
egress-proxies-0           1/1     Running   0          6m23s
egress-proxies-1           1/1     Running   0          6m22s
egress-proxies-2           1/1     Running   0          6m21s
...
```

### Test it out

- ensure you have some service on your tailnet that you can access via egress

#### Expose a tailnet service(s) on the ProxyGroup proxies

- Apply some egress `Services` with `tailscale.com/proxy-group` label, and a `tailscale.com/tailnet-ip` annotation pointing at the tailnet service i.e:

```
apiVersion: v1
kind: Service
metadata:
  annotations:
    tailscale.com/tailnet-ip: 100.64.1.230
  labels:
    tailscale.com/proxy-group: egress-proxies
  name: kuard-egress
spec:
  externalName: placeholder
  type: ExternalName
  ports:
  - port: 80
    protocol: TCP
    name: http
---
apiVersion: v1
kind: Service
metadata:
  annotations:
    tailscale.com/tailnet-ip: 100.64.1.196
  labels:
    tailscale.com/proxy-group: egress-proxies
  name: dns-server
spec:
  externalName: placeholder
  type: ExternalName
  ports:
  - port: 53
    protocol: UDP
    name: udp
  - port: 53
    protocol: TCP
    name: tcp
```

- Note- it will take a little while for the mounted ConfigMap to be updated.
To follow, you can take a look at whether the mounted config has been updated:
```
$ kubectl exec -it egress-proxies-0 -n tailscale -- cat /etc/egress-services/cfg

```
.. as well as check proxy logs
```
$ kubectl logs egress-proxies-0 -n tailscale
...
boot: 2024/09/04 07:35:48 running egress service reconfigure
boot: 2024/09/04 07:35:48 svc dns-server-default changes detected
boot: 2024/09/04 07:35:48 svc kuard-egress-default changes detected
...

```

- Once the config has been updated, test that any cluster workload can access the egress service(s)
via the ExternalName Service(s):

```
$ kubectl exec -it proxy -- sh
/ # curl -vv kuard-egress
* Host kuard-egress:80 was resolved.
...
/ # dig @dns-server <some-dns-name>

; <<>> DiG 9.18.24 <<>> @dns-server <some-dns-name> 
; (1 server found)
...
```

- Verify that the EndpointSlice created for each egress service contains all ProxyGroup Pod IPs:

```
$ kubectl get po -n tailscale -owide
NAME                       READY   STATUS    RESTARTS   AGE   IP           
egress-proxies-0           1/1     Running   0          31m   10.80.0.51
egress-proxies-1           1/1     Running   0          31m   10.80.2.54
egress-proxies-2           1/1     Running   0          31m   10.80.0.52
...
$ kubectl get endpointslice -n tailscale
NAME                   ADDRESSTYPE   PORTS       ENDPOINTS                          AGE
dns-server-default     IPv4          3160,2181   10.80.0.52,10.80.0.51,10.80.2.54   30m
kuard-egress-default   IPv4          2688        10.80.0.51,10.80.2.54,10.80.0.52   30m
...
```

#### Add another Pod to 'proxy group'

Scale replicas 3 -> 4:

- `$ kubectl scale sts/egress-proxies -n tailscale --replicas=4`

This change should be processed a lot faster as the proxy will read its config on start

- Once the additional `Pod` is up, observe that it's IP address has been added to the EndpointSlice:

```
$ kubectl get po -n tailscale -owide
NAME                       READY   STATUS    RESTARTS   AGE   IP           
egress-proxies-0           1/1     Running   0          41m   10.80.0.51   
egress-proxies-1           1/1     Running   0          41m   10.80.2.54   
egress-proxies-2           1/1     Running   0          41m   10.80.0.52   
egress-proxies-3           1/1     Running   0          69s   10.80.2.56   
...
$ kubectl get endpointslice -n tailscale
NAME                   ADDRESSTYPE   PORTS       ENDPOINTS                                      AGE
dns-server-default     IPv4          3160,2181   10.80.2.56,10.80.0.51,10.80.2.54 + 1 more...   40m
kuard-egress-default   IPv4          2688        10.80.0.51,10.80.2.54,10.80.0.52 + 1 more...   40m 
```

- You can also test that the new `Pod` knows how to route the traffic.

Find the `Pod`'s target port from the ExternalName Service that you created:

```
$ kubectl get svc kuard-egress -oyaml
apiVersion: v1
kind: Service
metadata:
  annotations:
    tailscale.com/tailnet-ip: 100.64.1.230
  labels:
    tailscale.com/proxy-group: egress-proxies
  name: kuard-egress
  namespace: default
spec:
  externalName: kuard-egress-default.tailscale.svc.cluster.local
  ports:
  - name: http
    port: 80
    protocol: TCP
    targetPort: 2688
  type: ExternalName
```
Try to route to the tailnet service using the new `Pod`'s IP:

```
$ kubectl exec -it proxy -- sh
/ # curl -vv 10.80.2.56:2688
*   Trying 10.80.2.56:2688...
* Connected to 10.80.2.56 (10.80.2.56) port 2688
...
```

#### Remove a Pod from the 'proxy group'

Scale replicas 4 -> 3:

- `$ kubectl scale sts/egress-proxies -n tailscale --replicas=3`

This change should get processed fairly fast.

- Observe that once the `Pod` is gone, it's IP address is removed from the `EndpointSlice`(s):

```
$ kubectl get po -n tailscale -owide
NAME                       READY   STATUS    RESTARTS   AGE   IP           
egress-proxies-0           1/1     Running   0          49m   10.80.0.51   
egress-proxies-1           1/1     Running   0          49m   10.80.2.54   
egress-proxies-2           1/1     Running   0          49m   10.80.0.52   
...
$ kubectl get endpointslice -n tailscale
NAME                   ADDRESSTYPE   PORTS       ENDPOINTS                          AGE
dns-server-default     IPv4          3160,2181   10.80.0.51,10.80.2.54,10.80.0.52   48m
kuard-egress-default   IPv4          2688        10.80.0.51,10.80.2.54,10.80.0.52   48m 
```
