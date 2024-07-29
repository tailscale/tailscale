# API Reference

## Packages
- [tailscale.com/v1alpha1](#tailscalecomv1alpha1)


## tailscale.com/v1alpha1


### Resource Types
- [Connector](#connector)
- [ConnectorList](#connectorlist)
- [DNSConfig](#dnsconfig)
- [DNSConfigList](#dnsconfiglist)
- [ProxyClass](#proxyclass)
- [ProxyClassList](#proxyclasslist)





#### Connector



Connector defines a Tailscale node that will be deployed in the cluster. The
node can be configured to act as a Tailscale subnet router and/or a Tailscale
exit node.
Connector is a cluster-scoped resource.
More info:
https://tailscale.com/kb/1236/kubernetes-operator#deploying-exit-nodes-and-subnet-routers-on-kubernetes-using-connector-custom-resource



_Appears in:_
- [ConnectorList](#connectorlist)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `tailscale.com/v1alpha1` | | |
| `kind` _string_ | `Connector` | | |
| `kind` _string_ | Kind is a string value representing the REST resource this object represents.<br />Servers may infer this from the endpoint the client submits requests to.<br />Cannot be updated.<br />In CamelCase.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds |  |  |
| `apiVersion` _string_ | APIVersion defines the versioned schema of this representation of an object.<br />Servers should convert recognized schemas to the latest internal value, and<br />may reject unrecognized values.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources |  |  |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.3/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[ConnectorSpec](#connectorspec)_ | ConnectorSpec describes the desired Tailscale component.<br />More info:<br />https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status |  |  |
| `status` _[ConnectorStatus](#connectorstatus)_ | ConnectorStatus describes the status of the Connector. This is set<br />and managed by the Tailscale operator. |  |  |


#### ConnectorList









| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `tailscale.com/v1alpha1` | | |
| `kind` _string_ | `ConnectorList` | | |
| `kind` _string_ | Kind is a string value representing the REST resource this object represents.<br />Servers may infer this from the endpoint the client submits requests to.<br />Cannot be updated.<br />In CamelCase.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds |  |  |
| `apiVersion` _string_ | APIVersion defines the versioned schema of this representation of an object.<br />Servers should convert recognized schemas to the latest internal value, and<br />may reject unrecognized values.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources |  |  |
| `metadata` _[ListMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.3/#listmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `items` _[Connector](#connector) array_ |  |  |  |


#### ConnectorSpec



ConnectorSpec describes a Tailscale node to be deployed in the cluster.



_Appears in:_
- [Connector](#connector)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `tags` _[Tags](#tags)_ | Tags that the Tailscale node will be tagged with.<br />Defaults to [tag:k8s].<br />To autoapprove the subnet routes or exit node defined by a Connector,<br />you can configure Tailscale ACLs to give these tags the necessary<br />permissions.<br />See https://tailscale.com/kb/1018/acls/#auto-approvers-for-routes-and-exit-nodes.<br />If you specify custom tags here, you must also make the operator an owner of these tags.<br />See  https://tailscale.com/kb/1236/kubernetes-operator/#setting-up-the-kubernetes-operator.<br />Tags cannot be changed once a Connector node has been created.<br />Tag values must be in form ^tag:[a-zA-Z][a-zA-Z0-9-]*$. |  | Pattern: `^tag:[a-zA-Z][a-zA-Z0-9-]*$` <br />Type: string <br /> |
| `hostname` _[Hostname](#hostname)_ | Hostname is the tailnet hostname that should be assigned to the<br />Connector node. If unset, hostname defaults to <connector<br />name>-connector. Hostname can contain lower case letters, numbers and<br />dashes, it must not start or end with a dash and must be between 2<br />and 63 characters long. |  | Pattern: `^[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$` <br />Type: string <br /> |
| `proxyClass` _string_ | ProxyClass is the name of the ProxyClass custom resource that<br />contains configuration options that should be applied to the<br />resources created for this Connector. If unset, the operator will<br />create resources with the default configuration. |  |  |
| `subnetRouter` _[SubnetRouter](#subnetrouter)_ | SubnetRouter defines subnet routes that the Connector node should<br />expose to tailnet. If unset, none are exposed.<br />https://tailscale.com/kb/1019/subnets/ |  |  |
| `exitNode` _boolean_ | ExitNode defines whether the Connector node should act as a<br />Tailscale exit node. Defaults to false.<br />https://tailscale.com/kb/1103/exit-nodes |  |  |


#### ConnectorStatus



ConnectorStatus defines the observed state of the Connector.



_Appears in:_
- [Connector](#connector)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.3/#condition-v1-meta) array_ | List of status conditions to indicate the status of the Connector.<br />Known condition types are `ConnectorReady`. |  |  |
| `subnetRoutes` _string_ | SubnetRoutes are the routes currently exposed to tailnet via this<br />Connector instance. |  |  |
| `isExitNode` _boolean_ | IsExitNode is set to true if the Connector acts as an exit node. |  |  |
| `tailnetIPs` _string array_ | TailnetIPs is the set of tailnet IP addresses (both IPv4 and IPv6)<br />assigned to the Connector node. |  |  |
| `hostname` _string_ | Hostname is the fully qualified domain name of the Connector node.<br />If MagicDNS is enabled in your tailnet, it is the MagicDNS name of the<br />node. |  |  |


#### Container







_Appears in:_
- [Pod](#pod)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `env` _[Env](#env) array_ | List of environment variables to set in the container.<br />https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#environment-variables<br />Note that environment variables provided here will take precedence<br />over Tailscale-specific environment variables set by the operator,<br />however running proxies with custom values for Tailscale environment<br />variables (i.e TS_USERSPACE) is not recommended and might break in<br />the future. |  |  |
| `image` _string_ | Container image name. By default images are pulled from<br />docker.io/tailscale/tailscale, but the official images are also<br />available at ghcr.io/tailscale/tailscale. Specifying image name here<br />will override any proxy image values specified via the Kubernetes<br />operator's Helm chart values or PROXY_IMAGE env var in the operator<br />Deployment.<br />https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#image |  |  |
| `imagePullPolicy` _[PullPolicy](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.3/#pullpolicy-v1-core)_ | Image pull policy. One of Always, Never, IfNotPresent. Defaults to Always.<br />https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#image |  | Enum: [Always Never IfNotPresent] <br /> |
| `resources` _[ResourceRequirements](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.3/#resourcerequirements-v1-core)_ | Container resource requirements.<br />By default Tailscale Kubernetes operator does not apply any resource<br />requirements. The amount of resources required wil depend on the<br />amount of resources the operator needs to parse, usage patterns and<br />cluster size.<br />https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#resources |  |  |
| `securityContext` _[SecurityContext](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.3/#securitycontext-v1-core)_ | Container security context.<br />Security context specified here will override the security context by the operator.<br />By default the operator:<br />- sets 'privileged: true' for the init container<br />- set NET_ADMIN capability for tailscale container for proxies that<br />are created for Services or Connector.<br />https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#security-context |  |  |


#### DNSConfig



DNSConfig can be deployed to cluster to make a subset of Tailscale MagicDNS
names resolvable by cluster workloads. Use this if: A) you need to refer to
tailnet services, exposed to cluster via Tailscale Kubernetes operator egress
proxies by the MagicDNS names of those tailnet services (usually because the
services run over HTTPS)
B) you have exposed a cluster workload to the tailnet using Tailscale Ingress
and you also want to refer to the workload from within the cluster over the
Ingress's MagicDNS name (usually because you have some callback component
that needs to use the same URL as that used by a non-cluster client on
tailnet).
When a DNSConfig is applied to a cluster, Tailscale Kubernetes operator will
deploy a nameserver for ts.net DNS names and automatically populate it with records
for any Tailscale egress or Ingress proxies deployed to that cluster.
Currently you must manually update your cluster DNS configuration to add the
IP address of the deployed nameserver as a ts.net stub nameserver.
Instructions for how to do it:
https://kubernetes.io/docs/tasks/administer-cluster/dns-custom-nameservers/#configuration-of-stub-domain-and-upstream-nameserver-using-coredns (for CoreDNS),
https://cloud.google.com/kubernetes-engine/docs/how-to/kube-dns (for kube-dns).
Tailscale Kubernetes operator will write the address of a Service fronting
the nameserver to dsnconfig.status.nameserver.ip.
DNSConfig is a singleton - you must not create more than one.
NB: if you want cluster workloads to be able to refer to Tailscale Ingress
using its MagicDNS name, you must also annotate the Ingress resource with
tailscale.com/experimental-forward-cluster-traffic-via-ingress annotation to
ensure that the proxy created for the Ingress listens on its Pod IP address.
NB: Clusters where Pods get assigned IPv6 addresses only are currently not supported.



_Appears in:_
- [DNSConfigList](#dnsconfiglist)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `tailscale.com/v1alpha1` | | |
| `kind` _string_ | `DNSConfig` | | |
| `kind` _string_ | Kind is a string value representing the REST resource this object represents.<br />Servers may infer this from the endpoint the client submits requests to.<br />Cannot be updated.<br />In CamelCase.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds |  |  |
| `apiVersion` _string_ | APIVersion defines the versioned schema of this representation of an object.<br />Servers should convert recognized schemas to the latest internal value, and<br />may reject unrecognized values.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources |  |  |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.3/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[DNSConfigSpec](#dnsconfigspec)_ | Spec describes the desired DNS configuration.<br />More info:<br />https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status |  |  |
| `status` _[DNSConfigStatus](#dnsconfigstatus)_ | Status describes the status of the DNSConfig. This is set<br />and managed by the Tailscale operator. |  |  |


#### DNSConfigList









| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `tailscale.com/v1alpha1` | | |
| `kind` _string_ | `DNSConfigList` | | |
| `kind` _string_ | Kind is a string value representing the REST resource this object represents.<br />Servers may infer this from the endpoint the client submits requests to.<br />Cannot be updated.<br />In CamelCase.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds |  |  |
| `apiVersion` _string_ | APIVersion defines the versioned schema of this representation of an object.<br />Servers should convert recognized schemas to the latest internal value, and<br />may reject unrecognized values.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources |  |  |
| `metadata` _[ListMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.3/#listmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `items` _[DNSConfig](#dnsconfig) array_ |  |  |  |


#### DNSConfigSpec







_Appears in:_
- [DNSConfig](#dnsconfig)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `nameserver` _[Nameserver](#nameserver)_ | Configuration for a nameserver that can resolve ts.net DNS names<br />associated with in-cluster proxies for Tailscale egress Services and<br />Tailscale Ingresses. The operator will always deploy this nameserver<br />when a DNSConfig is applied. |  |  |


#### DNSConfigStatus







_Appears in:_
- [DNSConfig](#dnsconfig)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.3/#condition-v1-meta) array_ |  |  |  |
| `nameserver` _[NameserverStatus](#nameserverstatus)_ | Nameserver describes the status of nameserver cluster resources. |  |  |


#### Env







_Appears in:_
- [Container](#container)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _[Name](#name)_ | Name of the environment variable. Must be a C_IDENTIFIER. |  | Pattern: `^[-._a-zA-Z][-._a-zA-Z0-9]*$` <br />Type: string <br /> |
| `value` _string_ | Variable references $(VAR_NAME) are expanded using the previously defined<br /> environment variables in the container and any service environment<br />variables. If a variable cannot be resolved, the reference in the input<br />string will be unchanged. Double $$ are reduced to a single $, which<br />allows for escaping the $(VAR_NAME) syntax: i.e. "$$(VAR_NAME)" will<br />produce the string literal "$(VAR_NAME)". Escaped references will never<br />be expanded, regardless of whether the variable exists or not. Defaults<br />to "". |  |  |


#### Hostname

_Underlying type:_ _string_



_Validation:_
- Pattern: `^[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$`
- Type: string

_Appears in:_
- [ConnectorSpec](#connectorspec)



#### Image







_Appears in:_
- [Nameserver](#nameserver)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `repo` _string_ | Repo defaults to tailscale/k8s-nameserver. |  |  |
| `tag` _string_ | Tag defaults to operator's own tag. |  |  |


#### Metrics







_Appears in:_
- [ProxyClassSpec](#proxyclassspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `enable` _boolean_ | Setting enable to true will make the proxy serve Tailscale metrics<br />at <pod-ip>:9001/debug/metrics.<br />Defaults to false. |  |  |


#### Name

_Underlying type:_ _string_



_Validation:_
- Pattern: `^[-._a-zA-Z][-._a-zA-Z0-9]*$`
- Type: string

_Appears in:_
- [Env](#env)



#### Nameserver







_Appears in:_
- [DNSConfigSpec](#dnsconfigspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `image` _[Image](#image)_ | Nameserver image. |  |  |


#### NameserverStatus







_Appears in:_
- [DNSConfigStatus](#dnsconfigstatus)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `ip` _string_ | IP is the ClusterIP of the Service fronting the deployed ts.net nameserver.<br />Currently you must manually update your cluster DNS config to add<br />this address as a stub nameserver for ts.net for cluster workloads to be<br />able to resolve MagicDNS names associated with egress or Ingress<br />proxies.<br />The IP address will change if you delete and recreate the DNSConfig. |  |  |


#### Pod







_Appears in:_
- [StatefulSet](#statefulset)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `labels` _object (keys:string, values:string)_ | Labels that will be added to the proxy Pod.<br />Any labels specified here will be merged with the default labels<br />applied to the Pod by the Tailscale Kubernetes operator.<br />Label keys and values must be valid Kubernetes label keys and values.<br />https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#syntax-and-character-set |  |  |
| `annotations` _object (keys:string, values:string)_ | Annotations that will be added to the proxy Pod.<br />Any annotations specified here will be merged with the default<br />annotations applied to the Pod by the Tailscale Kubernetes operator.<br />Annotations must be valid Kubernetes annotations.<br />https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/#syntax-and-character-set |  |  |
| `affinity` _[Affinity](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.3/#affinity-v1-core)_ | Proxy Pod's affinity rules.<br />By default, the Tailscale Kubernetes operator does not apply any affinity rules.<br />https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#affinity |  |  |
| `tailscaleContainer` _[Container](#container)_ | Configuration for the proxy container running tailscale. |  |  |
| `tailscaleInitContainer` _[Container](#container)_ | Configuration for the proxy init container that enables forwarding. |  |  |
| `securityContext` _[PodSecurityContext](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.3/#podsecuritycontext-v1-core)_ | Proxy Pod's security context.<br />By default Tailscale Kubernetes operator does not apply any Pod<br />security context.<br />https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#security-context-2 |  |  |
| `imagePullSecrets` _[LocalObjectReference](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.3/#localobjectreference-v1-core) array_ | Proxy Pod's image pull Secrets.<br />https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#PodSpec |  |  |
| `nodeName` _string_ | Proxy Pod's node name.<br />https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#scheduling |  |  |
| `nodeSelector` _object (keys:string, values:string)_ | Proxy Pod's node selector.<br />By default Tailscale Kubernetes operator does not apply any node<br />selector.<br />https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#scheduling |  |  |
| `tolerations` _[Toleration](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.3/#toleration-v1-core) array_ | Proxy Pod's tolerations.<br />By default Tailscale Kubernetes operator does not apply any<br />tolerations.<br />https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#scheduling |  |  |


#### ProxyClass



ProxyClass describes a set of configuration parameters that can be applied to
proxy resources created by the Tailscale Kubernetes operator.
To apply a given ProxyClass to resources created for a tailscale Ingress or
Service, use tailscale.com/proxy-class=<proxyclass-name> label. To apply a
given ProxyClass to resources created for a Connector, use
connector.spec.proxyClass field.
ProxyClass is a cluster scoped resource.
More info:
https://tailscale.com/kb/1236/kubernetes-operator#cluster-resource-customization-using-proxyclass-custom-resource.



_Appears in:_
- [ProxyClassList](#proxyclasslist)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `tailscale.com/v1alpha1` | | |
| `kind` _string_ | `ProxyClass` | | |
| `kind` _string_ | Kind is a string value representing the REST resource this object represents.<br />Servers may infer this from the endpoint the client submits requests to.<br />Cannot be updated.<br />In CamelCase.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds |  |  |
| `apiVersion` _string_ | APIVersion defines the versioned schema of this representation of an object.<br />Servers should convert recognized schemas to the latest internal value, and<br />may reject unrecognized values.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources |  |  |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.3/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[ProxyClassSpec](#proxyclassspec)_ | Specification of the desired state of the ProxyClass resource.<br />https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status |  |  |
| `status` _[ProxyClassStatus](#proxyclassstatus)_ | Status of the ProxyClass. This is set and managed automatically.<br />https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status |  |  |


#### ProxyClassList









| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `tailscale.com/v1alpha1` | | |
| `kind` _string_ | `ProxyClassList` | | |
| `kind` _string_ | Kind is a string value representing the REST resource this object represents.<br />Servers may infer this from the endpoint the client submits requests to.<br />Cannot be updated.<br />In CamelCase.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds |  |  |
| `apiVersion` _string_ | APIVersion defines the versioned schema of this representation of an object.<br />Servers should convert recognized schemas to the latest internal value, and<br />may reject unrecognized values.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources |  |  |
| `metadata` _[ListMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.3/#listmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `items` _[ProxyClass](#proxyclass) array_ |  |  |  |


#### ProxyClassSpec







_Appears in:_
- [ProxyClass](#proxyclass)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `statefulSet` _[StatefulSet](#statefulset)_ | Configuration parameters for the proxy's StatefulSet. Tailscale<br />Kubernetes operator deploys a StatefulSet for each of the user<br />configured proxies (Tailscale Ingress, Tailscale Service, Connector). |  |  |
| `metrics` _[Metrics](#metrics)_ | Configuration for proxy metrics. Metrics are currently not supported<br />for egress proxies and for Ingress proxies that have been configured<br />with tailscale.com/experimental-forward-cluster-traffic-via-ingress<br />annotation. Note that the metrics are currently considered unstable<br />and will likely change in breaking ways in the future - we only<br />recommend that you use those for debugging purposes. |  |  |
| `tailscale` _[TailscaleConfig](#tailscaleconfig)_ | TailscaleConfig contains options to configure the tailscale-specific<br />parameters of proxies. |  |  |


#### ProxyClassStatus







_Appears in:_
- [ProxyClass](#proxyclass)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.3/#condition-v1-meta) array_ | List of status conditions to indicate the status of the ProxyClass.<br />Known condition types are `ProxyClassReady`. |  |  |


#### Route

_Underlying type:_ _string_



_Validation:_
- Format: cidr
- Type: string

_Appears in:_
- [Routes](#routes)



#### Routes

_Underlying type:_ _[Route](#route)_



_Validation:_
- Format: cidr
- MinItems: 1
- Type: string

_Appears in:_
- [SubnetRouter](#subnetrouter)



#### StatefulSet







_Appears in:_
- [ProxyClassSpec](#proxyclassspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `labels` _object (keys:string, values:string)_ | Labels that will be added to the StatefulSet created for the proxy.<br />Any labels specified here will be merged with the default labels<br />applied to the StatefulSet by the Tailscale Kubernetes operator as<br />well as any other labels that might have been applied by other<br />actors.<br />Label keys and values must be valid Kubernetes label keys and values.<br />https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#syntax-and-character-set |  |  |
| `annotations` _object (keys:string, values:string)_ | Annotations that will be added to the StatefulSet created for the proxy.<br />Any Annotations specified here will be merged with the default annotations<br />applied to the StatefulSet by the Tailscale Kubernetes operator as<br />well as any other annotations that might have been applied by other<br />actors.<br />Annotations must be valid Kubernetes annotations.<br />https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/#syntax-and-character-set |  |  |
| `pod` _[Pod](#pod)_ | Configuration for the proxy Pod. |  |  |


#### SubnetRouter



SubnetRouter defines subnet routes that should be exposed to tailnet via a
Connector node.



_Appears in:_
- [ConnectorSpec](#connectorspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `advertiseRoutes` _[Routes](#routes)_ | AdvertiseRoutes refer to CIDRs that the subnet router should make<br />available. Route values must be strings that represent a valid IPv4<br />or IPv6 CIDR range. Values can be Tailscale 4via6 subnet routes.<br />https://tailscale.com/kb/1201/4via6-subnets/ |  | Format: cidr <br />MinItems: 1 <br />Type: string <br /> |


#### Tag

_Underlying type:_ _string_



_Validation:_
- Pattern: `^tag:[a-zA-Z][a-zA-Z0-9-]*$`
- Type: string

_Appears in:_
- [Tags](#tags)



#### Tags

_Underlying type:_ _[Tag](#tag)_



_Validation:_
- Pattern: `^tag:[a-zA-Z][a-zA-Z0-9-]*$`
- Type: string

_Appears in:_
- [ConnectorSpec](#connectorspec)



#### TailscaleConfig







_Appears in:_
- [ProxyClassSpec](#proxyclassspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `acceptRoutes` _boolean_ | AcceptRoutes can be set to true to make the proxy instance accept<br />routes advertized by other nodes on the tailnet, such as subnet<br />routes.<br />This is equivalent of passing --accept-routes flag to a tailscale Linux client.<br />https://tailscale.com/kb/1019/subnets#use-your-subnet-routes-from-other-machines<br />Defaults to false. |  |  |


