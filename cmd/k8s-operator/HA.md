To try out:
(This is the order in which I am testing this prototype. It may or may not work in a different order)
- from this branch run
```
helm upgrade --install operator ./cmd/k8s-operator/deploy/chart/ -n tailscale  --set operatorConfig.image.repo=gcr.io/csi-test-290908/operator --set operatorConfig.image.tag=v0.0.16proxycidr --set proxyConfig.image.repo=gcr.io/csi-test-290908/proxy --set proxyConfig.image.tag=v0.0.15proxycidr  --set oauth.clientId=<oauth-client-id> --set oauth.clientSecret=<oauth-client-secret> operatorConfig.logging=debug --create-namespace
```

- run `kubectl apply -f ./cmd/k8s-operator/deploy/examples/clusterconfig.yaml`
^ but you want to modify the domain before to not point at my tailnet
This will create an STS with 4 replicas in tailscale namespace

- create some cluster ingress Service
Each proxy should set up firewall rules to expose the service on one of the IPs it's advertizing 

- to test that it works so far- for one of the proxies, figure out what service IP it is advertizing the
cluster service on (i.e by looking at proxies-0 ConfigMap in tailscale namespace) and attempt
to access that from a client that has `--accept-routes` set to true.

- run `kubectl apply -f ./cmd/k8s-operator/deploy/examples/dnsconfig.yaml`
This will create a nameserver that is currently not on tailnet.
You should be able to <dig @nameservers-cluster-ip <dns-name-of-your-service> and get back one of the tailnet IPs that the proxies expose this service on. 

Next steps:
- expose the nameserver, maybe on an  operator egress?

Notes:
- right now, machines hardcoded to 4, range hardcoded to "100.64.2.0/26", "100.64.2.64/26", "100.64.2.128/26", "100.64.2.192/26"
Operator creates a StatefulSet with 4 replicas for an applied ClusterConfig
