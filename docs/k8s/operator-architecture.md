# Operator architecture diagrams

The Tailscale Kubernetes operator has a collection of use-cases that can be
mixed and matched as required. The following diagrams illustrate how the
operator implements each use-case.

In each diagram, the "tailscale" namespace is entirely managed by the operator
once the operator itself has been deployed.

Tailscale devices are highlighted as black nodes. The salient devices for each
use-case are marked as "src" or "dst" to denote which node is a source or a
destination in the context of ACL rules that will apply to network traffic.

## API server proxy

[Documentation][kb-operator-proxy]

The operator runs the API server proxy in-process. If the proxy is running in
"noauth" mode, it forwards HTTP requests unmodified. If the proxy is running in
"auth" mode, it deletes any existing auth headers and adds impersonation
headers to the request before forwarding to the API server.

```mermaid
%%{ init: { 'theme':'neutral' } }%%
flowchart LR
    classDef tsnode color:#fff,fill:#000;
    classDef pod fill:#fff;

    subgraph Key
        ts[Tailscale device]:::tsnode
        pod((Pod)):::pod
    end

    subgraph k8s[Kubernetes cluster]
        subgraph tailscale-ns[ns=tailscale]
            operator(("operator (dst)")):::tsnode
        end

        subgraph controlplane["Control plane"]
            api[kube-apiserver]
        end
    end
    client["client (src)"]:::tsnode --> operator
    operator-->|proxies requests with impersonation headers| api

```

## L3 ingress

[Documentation][kb-operator-l3-ingress]

The user deploys an app to the default namespace, and creates a normal Service
that selects the app's pods. Add the annotation `tailscale.com/expose: "true"`
to the Service, and the operator will create an ingress proxy that allows
devices anywhere on the tailnet to access the Service.

```mermaid
%%{ init: { 'theme':'neutral' } }%%
flowchart TD
    classDef tsnode color:#fff,fill:#000;
    classDef pod fill:#fff;

    subgraph Key
        ts[Tailscale device]:::tsnode
        pod((Pod)):::pod
        foo1-->|WireGuard traffic|foo2
        foo3-->|Plaintext traffic|foo4
    end

    subgraph k8s[Kubernetes cluster]
        subgraph tailscale-ns[ns=tailscale]
            operator((operator)):::tsnode
            ingress(("ingress proxy (dst)")):::tsnode
            secret[config Secret]
        end

        subgraph defaultns[ns=default]
            svc[annotated Service]
            svc --> pod1((pod1))
            svc --> pod2((pod2))
        end
    end
    client["client (src)"]:::tsnode --> ingress
    ingress -->|forwards traffic| svc
    operator -.->|creates| ingress
    operator -.->|reads| svc
    operator -.->|creates| secret
    secret -.->|mounted| ingress

```

## L7 ingress

[Documentation][kb-operator-l7-ingress]

## L3 egress

[Documentation][kb-operator-l3-egress]

1. The user deploys a Service named `db` with `type: ExternalName` and an annotation 
  `tailscale.com/tailnet-fqdn: db.tails-scales.ts.net`.
1. The operator creates a proxy Pod managed by a single replica StatefulSet, and a headless Service pointing at the proxy Pod.
1. The operator updates the `db` Service's `spec.externalName` field to point
  at the headless Service it created in the previous step.

(Optional) If the user also adds the `tailscale.com/proxy-group: egress-proxies`
annotation to their `db` Service, the operator will skip creating a proxy Pod and
instead point the headless Service at the existing ProxyGroup's pods. In this
case, ports are also required in the `db` Service spec.

Note, in some cases, the config and the state Secret may be the same Kubernetes Secret.

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
        subgraph tailscale-ns[ns=tailscale]
            operator((operator)):::tsnode
            egress(("egress proxy (src)")):::tsnode
            headless-svc[headless svc]
            cfg-secret["config Secret"]
            state-secret["state Secret"]
        end

        subgraph defaultns[ns=default]
            svc[db ExternalName svc]
            pod1((pod1)) --> svc
            pod2((pod2)) --> svc
        end
    end
    node["db.tails-scales.ts.net (dst)"]:::tsnode
    svc -->|DNS points to| headless-svc
    headless-svc -->|forwards traffic| egress
    egress -->|forwards traffic| node
    operator -.->|creates| egress
    operator -.->|creates| headless-svc
    operator -.->|creates| cfg-secret
    operator -.->|watches & updates| svc
    cfg-secret -.->|mounted| egress
    egress -.->|stores state| state-secret

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
        subgraph tailscale-ns[ns=tailscale]
            operator((operator)):::tsnode
            pg-sts[pg StatefulSet]
            pg-0(("pg-0 (src)")):::tsnode
            pg-1(("pg-1 (src)")):::tsnode
            cfg-secret-0["pg-0-config Secret"]
            cfg-secret-1["pg-1-config Secret"]
            state-secret-0["pg-0 Secret"]
            state-secret-1["pg-1 Secret"]
        end

        subgraph cluster-scope["Cluster scoped resources"]
            pg["pg ProxyGroup"]
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

## Subnet routers and exit nodes

[Documentation][kb-operator-connector]

## Recorder nodes

[Documentation][kb-operator-recorder]

The `Recorder` custom resource makes it easier to deploy `tsrecorder` to a cluster.
It currently only supports a single replica.

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
        subgraph tailscale-ns[ns=tailscale]
            operator((operator)):::tsnode
            rec-sts[rec StatefulSet]
            rec-0(("rec-0 Pod (tsrecorder)")):::tsnode
            cfg-secret-0["rec-0-config Secret"]
            state-secret-0["rec-0 Secret"]
        end

        subgraph cluster-scope["Cluster scoped resources"]
            rec["rec Recorder"]
        end
    end
    operator-.->|watches| rec
    operator -.->|creates| rec-sts
    rec-sts -.->|manages| rec-0
    operator -.->|creates| cfg-secret-0
    cfg-secret-0 -.->|mounted| rec-0
    rec-0 -.->|stores state| state-secret-0

```

[kb-operator-proxy]: https://tailscale.com/kb/1437/kubernetes-operator-api-server-proxy
[kb-operator-l3-ingress]: https://tailscale.com/kb/1439/kubernetes-operator-cluster-ingress#exposing-a-cluster-workload-using-a-kubernetes-service
[kb-operator-l7-ingress]: https://tailscale.com/kb/1439/kubernetes-operator-cluster-ingress#exposing-cluster-workloads-using-a-kubernetes-ingress
[kb-operator-l3-egress]: https://tailscale.com/kb/1438/kubernetes-operator-cluster-egress
[kb-operator-l3-egress-proxygroup]: TODO
[kb-operator-connector]: https://tailscale.com/kb/1441/kubernetes-operator-connector
[kb-operator-recorder]: TODO
