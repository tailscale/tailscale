# Operator architecture diagrams

The Tailscale Kubernetes operator has a collection of use-cases that can be
mixed and matched as required. The following diagrams illustrate how the
operator implements each use-case.

In each diagram, the "tailscale" namespace is entirely managed by the operator
once the operator itself has been deployed.

Tailscale devices are highlighted as black nodes. The salient devices for each
use-case are marked as "src" or "dst" to denote which node is a source or a
destination in the context of ACL rules that will apply to network traffic.

Note, in some cases, the config and the state Secret may be the same Kubernetes
Secret.

## API server proxy

[Documentation][kb-operator-proxy]

The operator runs the API server proxy in-process. If the proxy is running in
"noauth" mode, it forwards HTTP requests unmodified. If the proxy is running in
"auth" mode, it deletes any existing auth headers and adds
[impersonation headers][k8s-impersonation] to the request before forwarding to
the API server. A request with impersonation headers will look something like:

```
GET /api/v1/namespaces/default/pods HTTP/1.1
Host: k8s-api.example.com
Authorization: Bearer <operator-service-account-token>
Impersonate-Group: tailnet-readers
Accept: application/json
```

```mermaid
%%{ init: { 'theme':'neutral' } }%%
flowchart LR
    classDef tsnode color:#fff,fill:#000;
    classDef pod fill:#fff;

    subgraph Key
        ts[Tailscale device]:::tsnode
        pod((Pod)):::pod
        hidden[" "]-->|WireGuard traffic|hidden2[" "]
    end

    subgraph k8s[Kubernetes cluster]
        subgraph tailscale-ns[namespace=tailscale]
            operator(("operator (dst)")):::tsnode
        end

        subgraph controlplane["Control plane"]
            api[kube-apiserver]
        end
    end
    client["client (src)"]:::tsnode --> operator
    operator-->|"proxy (maybe with impersonation headers)"| api

    linkStyle 0 stroke:blue;
    linkStyle 1 stroke:blue;

```

## L3 ingress

[Documentation][kb-operator-l3-ingress]

The user deploys an app to the default namespace, and creates a normal Service
that selects the app's Pods. Either add the annotation
`tailscale.com/expose: "true"` or specify `.spec.type` as `Loadbalancer` and
`.spec.loadBalancerClass` as `tailscale`. The operator will create an ingress
proxy that allows devices anywhere on the tailnet to access the Service.

The proxy Pod uses `iptables` or `nftables` rules to DNAT traffic bound for the
proxy's tailnet IP to the Service's internal Cluster IP instead. This usually
means traffic coming in on `tailscale0` is forwarded to the `eth0` interface.

```mermaid
%%{ init: { 'theme':'neutral' } }%%
flowchart TD
    classDef tsnode color:#fff,fill:#000;
    classDef pod fill:#fff;

    subgraph Key
        ts[Tailscale device]:::tsnode
        pod((Pod)):::pod
        hidden[" "]-->|WireGuard traffic|hidden2[" "]
    end

    subgraph k8s[Kubernetes cluster]
        subgraph tailscale-ns[namespace=tailscale]
            operator((operator)):::tsnode
            ingress-sts["StatefulSet"]
            ingress(("ingress proxy (dst)")):::tsnode
            config-secret["config Secret"]
            state-secret["state Secret"]
        end

        subgraph defaultns[namespace=default]
            svc[annotated Service]
            svc --> pod1((pod1))
            svc --> pod2((pod2))
        end
    end
    client["client (src)"]:::tsnode --> ingress
    ingress -->|forwards traffic| svc
    operator -.->|creates| ingress-sts
    ingress-sts -.->|manages| ingress
    operator -.->|reads| svc
    operator -.->|creates| config-secret
    config-secret -.->|mounted| ingress
    ingress -.->|stores state| state-secret

    linkStyle 0 stroke:blue;
    linkStyle 3 stroke:blue;

```

## L7 ingress

[Documentation][kb-operator-l7-ingress]

L7 ingress is relatively similar to L3 ingress. It is configured via an
`Ingress` object instead of a `Service`, and uses `tailscale serve` to accept
traffic instead of configuring `iptables` or `nftables` rules. Note that we use
tailscaled's local API (`SetServeConfig`) to set serve config, not the
`tailscale serve` command.

```mermaid
%%{ init: { 'theme':'neutral' } }%%
flowchart TD
    classDef tsnode color:#fff,fill:#000;
    classDef pod fill:#fff;

    subgraph Key
        ts[Tailscale device]:::tsnode
        pod((Pod)):::pod
        hidden[" "]-->|WireGuard traffic|hidden2[" "]
    end

    subgraph k8s[Kubernetes cluster]
        subgraph tailscale-ns[namespace=tailscale]
            operator((operator)):::tsnode
            ingress-sts["StatefulSet"]
            ingress-pod(("ingress proxy (dst)")):::tsnode
            config-secret["config Secret"]
            state-secret["state Secret"]
        end

        subgraph defaultns[namespace=default]
            ingress[tailscale Ingress]
            svc["Service"]
            svc --> pod1((pod1))
            svc --> pod2((pod2))
        end
    end
    client["client (src)"]:::tsnode --> ingress-pod
    ingress-pod -->|forwards /api prefix traffic| svc
    operator -.->|creates| ingress-sts
    ingress-sts -.->|manages| ingress-pod
    operator -.->|reads| ingress
    operator -.->|creates| config-secret
    config-secret -.->|mounted| ingress-pod
    ingress-pod -.->|stores state| state-secret
    ingress -.->|/api prefix| svc

    linkStyle 0 stroke:blue;
    linkStyle 3 stroke:blue;

```

## L3 egress

[Documentation][kb-operator-l3-egress]

1. The user deploys a Service with `type: ExternalName` and an annotation 
  `tailscale.com/tailnet-fqdn: db.tails-scales.ts.net`.
1. The operator creates a proxy Pod managed by a single replica StatefulSet, and a headless Service pointing at the proxy Pod.
1. The operator updates the `ExternalName` Service's `spec.externalName` field to point
  at the headless Service it created in the previous step.

(Optional) If the user also adds the `tailscale.com/proxy-group: egress-proxies`
annotation to their `ExternalName` Service, the operator will skip creating a proxy Pod and
instead point the headless Service at the existing ProxyGroup's pods. In this
case, ports are also required in the `ExternalName` Service spec.

```mermaid
%%{ init: { 'theme':'neutral' } }%%

flowchart TD
    classDef tsnode color:#fff,fill:#000;
    classDef pod fill:#fff;

    subgraph Key
        ts[Tailscale device]:::tsnode
        pod((Pod)):::pod
        hidden[" "]-->|WireGuard traffic|hidden2[" "]
    end

    subgraph k8s[Kubernetes cluster]
        subgraph tailscale-ns[namespace=tailscale]
            operator((operator)):::tsnode
            egress(("egress proxy (src)")):::tsnode
            egress-sts["StatefulSet"]
            headless-svc[headless Service]
            cfg-secret["config Secret"]
            state-secret["state Secret"]
        end

        subgraph defaultns[namespace=default]
            svc[ExternalName Service]
            pod1((pod1)) --> svc
            pod2((pod2)) --> svc
        end
    end
    node["db.tails-scales.ts.net (dst)"]:::tsnode
    svc -->|DNS points to| headless-svc
    headless-svc -->|selects egress Pod| egress
    egress -->|forwards traffic| node
    operator -.->|creates| egress-sts
    egress-sts -.->|manages| egress
    operator -.->|creates| headless-svc
    operator -.->|creates| cfg-secret
    operator -.->|watches & updates| svc
    cfg-secret -.->|mounted| egress
    egress -.->|stores state| state-secret

    linkStyle 0 stroke:blue;
    linkStyle 5 stroke:blue;

```

## `ProxyGroup`

[Documentation][kb-operator-l3-egress-proxygroup]

The `ProxyGroup` custom resource manages a collection of proxy Pods that can be
configured to egress traffic out of the cluster via ExternalName Services defined
elsewhere. They will also support ingress in the future. In this diagram, the
`ProxyGroup` is named `pg`, and the operator creates proxy pods, via a StatefulSet
but they don't yet serve any traffic.

`ProxyGroups` currently only support egress (see above).

```mermaid
%%{ init: { 'theme':'neutral' } }%%

flowchart TD
    classDef tsnode color:#fff,fill:#000;
    classDef pod fill:#fff;

    subgraph Key
        ts[Tailscale device]:::tsnode
        pod((Pod)):::pod
    end

    subgraph k8s[Kubernetes cluster]
        subgraph tailscale-ns[namespace=tailscale]
            operator((operator)):::tsnode
            pg-sts[StatefulSet]
            pg-0(("pg-0 (src)")):::tsnode
            pg-1(("pg-1 (src)")):::tsnode
            cfg-secret-0["Secret 'pg-0-config'"]
            cfg-secret-1["Secret 'pg-1-config'"]
            state-secret-0["Secret 'pg-0'"]
            state-secret-1["Secret 'pg-1'"]
        end

        subgraph cluster-scope["Cluster scoped resources"]
            pg["ProxyGroup 'pg'"]
        end
    end
    operator-.->|watches| pg
    operator -.->|creates| pg-sts
    pg-sts -.->|manages| pg-0
    pg-sts -.->|manages| pg-1
    operator -.->|creates| cfg-secret-0
    operator -.->|creates| cfg-secret-1
    cfg-secret-0 -.->|mounted| pg-0
    cfg-secret-1 -.->|mounted| pg-1
    pg-0 -.->|stores state| state-secret-0
    pg-1 -.->|stores state| state-secret-1

```

## Connector

[Subnet router and exit node documentation][kb-operator-connector]

[App connector documentation][kb-operator-app-connector]

The Connector Custom Resource can deploy either a subnet router, an exit node,
or an app connector. The following diagram shows all 3, but only one workflow
can be configured per Connector resource.

```mermaid
%%{ init: { 'theme':'neutral' } }%%

flowchart TD
    classDef tsnode color:#fff,fill:#000;
    classDef pod fill:#fff;
    classDef hidden display:none;

    subgraph Key
        ts[Tailscale device]:::tsnode
        pod((Pod)):::pod
        hidden[" "]-->|WireGuard traffic|hidden2[" "]
    end

    subgraph grouping[" "]
        subgraph k8s[Kubernetes cluster]
            subgraph tailscale-ns[namespace=tailscale]
                operator((operator)):::tsnode
                cn-sts[StatefulSet]
                cn-pod(("tailscale (dst)")):::tsnode
                cfg-secret["config Secret"]
                state-secret["state Secret"]
            end

            subgraph cluster-scope["Cluster scoped resources"]
                cn["Connector"]
            end

            subgraph defaultns["namespace=default"]
                pod1
            end
        end

        client["client (src)"]:::tsnode
        Internet
    end

    client-->cn-pod
    cn-pod-->|app connector or exit node routes| Internet
    cn-pod-->|subnet route| pod1
    operator-.->|watches| cn
    operator -.->|creates| cn-sts
    cn-sts -.->|manages| cn-pod
    operator -.->|creates| cfg-secret
    cfg-secret -.->|mounted| cn-pod
    cn-pod -.->|stores state| state-secret

    class grouping hidden
    linkStyle 0 stroke:blue;
    linkStyle 1 stroke:blue;

```

## Recorder nodes

[Documentation][kb-operator-recorder]

The `Recorder` custom resource makes it easier to deploy `tsrecorder` to a cluster.
It currently only supports a single replica.

```mermaid
%%{ init: { 'theme':'neutral' } }%%

flowchart TD
    classDef tsnode color:#fff,fill:#000;
    classDef pod fill:#fff;
    classDef hidden display:none;

    subgraph Key
        ts[Tailscale device]:::tsnode
        pod((Pod)):::pod
        hidden[" "]-->|WireGuard traffic|hidden2[" "]
    end

    subgraph grouping[" "]
        subgraph k8s[Kubernetes cluster]
            subgraph tailscale-ns[namespace=tailscale]
                operator((operator)):::tsnode
                rec-sts[StatefulSet]
                rec-0(("tsrecorder")):::tsnode
                cfg-secret-0["config Secret"]
                state-secret-0["state Secret"]
            end

            subgraph cluster-scope["Cluster scoped resources"]
                rec["Recorder"]
            end
        end

        client["client (src)"]:::tsnode
        server["server (dst)"]:::tsnode
        s3["S3-compatible storage"]
    end

    client-->|ssh session|server
    server-->|ssh session recording|rec-0
    rec-0-->s3
    operator-.->|watches| rec
    operator -.->|creates| rec-sts
    rec-sts -.->|manages| rec-0
    operator -.->|creates| cfg-secret-0
    cfg-secret-0 -.->|mounted| rec-0
    rec-0 -.->|stores state| state-secret-0

    class grouping hidden
    linkStyle 0 stroke:blue;
    linkStyle 1 stroke:blue;
    linkStyle 2 stroke:blue;

```

[kb-operator-proxy]: https://tailscale.com/kb/1437/kubernetes-operator-api-server-proxy
[kb-operator-l3-ingress]: https://tailscale.com/kb/1439/kubernetes-operator-cluster-ingress#exposing-a-cluster-workload-using-a-kubernetes-service
[kb-operator-l7-ingress]: https://tailscale.com/kb/1439/kubernetes-operator-cluster-ingress#exposing-cluster-workloads-using-a-kubernetes-ingress
[kb-operator-l3-egress]: https://tailscale.com/kb/1438/kubernetes-operator-cluster-egress
[kb-operator-l3-egress-proxygroup]: https://tailscale.com/kb/1438/kubernetes-operator-cluster-egress#configure-an-egress-service-using-proxygroup
[kb-operator-connector]: https://tailscale.com/kb/1441/kubernetes-operator-connector
[kb-operator-app-connector]: https://tailscale.com/kb/1517/kubernetes-operator-app-connector
[kb-operator-recorder]: https://tailscale.com/kb/1484/kubernetes-operator-deploying-tsrecorder
[k8s-impersonation]: https://kubernetes.io/docs/reference/access-authn-authz/authentication/#user-impersonation