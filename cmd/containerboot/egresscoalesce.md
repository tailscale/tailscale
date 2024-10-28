This is a prototype for how to make any tailnet service accessible from cluster without creating individual egress Services for each.

## To try it out

- create a reusable auth key and update ./egressc.yaml with it

- kubectl apply -f ./egressc.yaml

- update kube-dns/CoreDNS to route all traffic for ts.net to 100.100.100.100 i.e

```
data:
    stubDomains: |
      {
        "ts.net": [
          "100.100.100.100"
        ]
      }
```
^ for kube-dns

See CoreDNS example in https://tailscale.com/kb/1438/kubernetes-operator-cluster-egress#expose-a-tailnet-https-service-to-your-cluster-workloads

- any Pod in cluster should now be able to access any tailnet service by ts.net DNS name

## Caveats

!!! I have only tested this on GKE with kube-dns

Also:

- a Tailscale DaemonSet is needed which will likely make resource consumption too high for many-node cluster 
- only works on hosts that support iptables
- will not work with GCP CloudDNS or any other DNS service that is outside cluster/cannot route to Pods

## How it works:

- creates a DaemonSet that runs Tailscale (NOT on host network)

- the DaemonSet has a single container that runs Tailscale and an init container

- the init container for each DaemonSet's Pod creates a Job that runs once on the Pod's node and sets up route to route 100.64.0.0/10 to this Pod

- the container runs updated containerboot that runs ARP resolver in a loop and responds to ARP requests for IPs in 100.64.0.0/10 range with the Pod's MAC address

## Next steps:

- try to figure out if the same can be achieved with a smaller number of Tailscale Pods. The problem there is how to set up routing to Pods across hosts