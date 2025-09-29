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
- [ProxyGroup](#proxygroup)
- [ProxyGroupList](#proxygrouplist)
- [Recorder](#recorder)
- [RecorderList](#recorderlist)



#### APIServerProxyMode

_Underlying type:_ _string_



_Validation:_
- Enum: [auth noauth]
- Type: string

_Appears in:_
- [KubeAPIServerConfig](#kubeapiserverconfig)



#### AppConnector



AppConnector defines a Tailscale app connector node configured via Connector.



_Appears in:_
- [ConnectorSpec](#connectorspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `routes` _[Routes](#routes)_ | Routes are optional preconfigured routes for the domains routed via the app connector.<br />If not set, routes for the domains will be discovered dynamically.<br />If set, the app connector will immediately be able to route traffic using the preconfigured routes, but may<br />also dynamically discover other routes.<br />https://tailscale.com/kb/1332/apps-best-practices#preconfiguration |  | Format: cidr <br />MinItems: 1 <br />Type: string <br /> |




#### Connector



Connector defines a Tailscale node that will be deployed in the cluster. The
node can be configured to act as a Tailscale subnet router and/or a Tailscale
exit node.
Connector is a cluster-scoped resource.
More info:
https://tailscale.com/kb/1441/kubernetes-operator-connector



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


#### ConnectorDevice







_Appears in:_
- [ConnectorStatus](#connectorstatus)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `hostname` _string_ | Hostname is the fully qualified domain name of the Connector replica.<br />If MagicDNS is enabled in your tailnet, it is the MagicDNS name of the<br />node. |  |  |
| `tailnetIPs` _string array_ | TailnetIPs is the set of tailnet IP addresses (both IPv4 and IPv6)<br />assigned to the Connector replica. |  |  |


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
| `tags` _[Tags](#tags)_ | Tags that the Tailscale node will be tagged with.<br />Defaults to [tag:k8s].<br />To autoapprove the subnet routes or exit node defined by a Connector,<br />you can configure Tailscale ACLs to give these tags the necessary<br />permissions.<br />See https://tailscale.com/kb/1337/acl-syntax#autoapprovers.<br />If you specify custom tags here, you must also make the operator an owner of these tags.<br />See  https://tailscale.com/kb/1236/kubernetes-operator/#setting-up-the-kubernetes-operator.<br />Tags cannot be changed once a Connector node has been created.<br />Tag values must be in form ^tag:[a-zA-Z][a-zA-Z0-9-]*$. |  | Pattern: `^tag:[a-zA-Z][a-zA-Z0-9-]*$` <br />Type: string <br /> |
| `hostname` _[Hostname](#hostname)_ | Hostname is the tailnet hostname that should be assigned to the<br />Connector node. If unset, hostname defaults to <connector<br />name>-connector. Hostname can contain lower case letters, numbers and<br />dashes, it must not start or end with a dash and must be between 2<br />and 63 characters long. This field should only be used when creating a connector<br />with an unspecified number of replicas, or a single replica. |  | Pattern: `^[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$` <br />Type: string <br /> |
| `hostnamePrefix` _[HostnamePrefix](#hostnameprefix)_ | HostnamePrefix specifies the hostname prefix for each<br />replica. Each device will have the integer number<br />from its StatefulSet pod appended to this prefix to form the full hostname.<br />HostnamePrefix can contain lower case letters, numbers and dashes, it<br />must not start with a dash and must be between 1 and 62 characters long. |  | Pattern: `^[a-z0-9][a-z0-9-]{0,61}$` <br />Type: string <br /> |
| `proxyClass` _string_ | ProxyClass is the name of the ProxyClass custom resource that<br />contains configuration options that should be applied to the<br />resources created for this Connector. If unset, the operator will<br />create resources with the default configuration. |  |  |
| `subnetRouter` _[SubnetRouter](#subnetrouter)_ | SubnetRouter defines subnet routes that the Connector device should<br />expose to tailnet as a Tailscale subnet router.<br />https://tailscale.com/kb/1019/subnets/<br />If this field is unset, the device does not get configured as a Tailscale subnet router.<br />This field is mutually exclusive with the appConnector field. |  |  |
| `appConnector` _[AppConnector](#appconnector)_ | AppConnector defines whether the Connector device should act as a Tailscale app connector. A Connector that is<br />configured as an app connector cannot be a subnet router or an exit node. If this field is unset, the<br />Connector does not act as an app connector.<br />Note that you will need to manually configure the permissions and the domains for the app connector via the<br />Admin panel.<br />Note also that the main tested and supported use case of this config option is to deploy an app connector on<br />Kubernetes to access SaaS applications available on the public internet. Using the app connector to expose<br />cluster workloads or other internal workloads to tailnet might work, but this is not a use case that we have<br />tested or optimised for.<br />If you are using the app connector to access SaaS applications because you need a predictable egress IP that<br />can be whitelisted, it is also your responsibility to ensure that cluster traffic from the connector flows<br />via that predictable IP, for example by enforcing that cluster egress traffic is routed via an egress NAT<br />device with a static IP address.<br />https://tailscale.com/kb/1281/app-connectors |  |  |
| `exitNode` _boolean_ | ExitNode defines whether the Connector device should act as a Tailscale exit node. Defaults to false.<br />This field is mutually exclusive with the appConnector field.<br />https://tailscale.com/kb/1103/exit-nodes |  |  |
| `replicas` _integer_ | Replicas specifies how many devices to create. Set this to enable<br />high availability for app connectors, subnet routers, or exit nodes.<br />https://tailscale.com/kb/1115/high-availability. Defaults to 1. |  | Minimum: 0 <br /> |


#### ConnectorStatus



ConnectorStatus defines the observed state of the Connector.



_Appears in:_
- [Connector](#connector)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.3/#condition-v1-meta) array_ | List of status conditions to indicate the status of the Connector.<br />Known condition types are `ConnectorReady`. |  |  |
| `subnetRoutes` _string_ | SubnetRoutes are the routes currently exposed to tailnet via this<br />Connector instance. |  |  |
| `isExitNode` _boolean_ | IsExitNode is set to true if the Connector acts as an exit node. |  |  |
| `isAppConnector` _boolean_ | IsAppConnector is set to true if the Connector acts as an app connector. |  |  |
| `tailnetIPs` _string array_ | TailnetIPs is the set of tailnet IP addresses (both IPv4 and IPv6)<br />assigned to the Connector node. |  |  |
| `hostname` _string_ | Hostname is the fully qualified domain name of the Connector node.<br />If MagicDNS is enabled in your tailnet, it is the MagicDNS name of the<br />node. When using multiple replicas, this field will be populated with the<br />first replica's hostname. Use the Hostnames field for the full list<br />of hostnames. |  |  |
| `devices` _[ConnectorDevice](#connectordevice) array_ | Devices contains information on each device managed by the Connector resource. |  |  |


#### Container







_Appears in:_
- [Pod](#pod)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `env` _[Env](#env) array_ | List of environment variables to set in the container.<br />https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#environment-variables<br />Note that environment variables provided here will take precedence<br />over Tailscale-specific environment variables set by the operator,<br />however running proxies with custom values for Tailscale environment<br />variables (i.e TS_USERSPACE) is not recommended and might break in<br />the future. |  |  |
| `image` _string_ | Container image name. By default images are pulled from docker.io/tailscale,<br />but the official images are also available at ghcr.io/tailscale.<br />For all uses except on ProxyGroups of type "kube-apiserver", this image must<br />be either tailscale/tailscale, or an equivalent mirror of that image.<br />To apply to ProxyGroups of type "kube-apiserver", this image must be<br />tailscale/k8s-proxy or a mirror of that image.<br />For "tailscale/tailscale"-based proxies, specifying image name here will<br />override any proxy image values specified via the Kubernetes operator's<br />Helm chart values or PROXY_IMAGE env var in the operator Deployment.<br />For "tailscale/k8s-proxy"-based proxies, there is currently no way to<br />configure your own default, and this field is the only way to use a<br />custom image.<br />https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#image |  |  |
| `imagePullPolicy` _[PullPolicy](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.3/#pullpolicy-v1-core)_ | Image pull policy. One of Always, Never, IfNotPresent. Defaults to Always.<br />https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#image |  | Enum: [Always Never IfNotPresent] <br /> |
| `resources` _[ResourceRequirements](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.3/#resourcerequirements-v1-core)_ | Container resource requirements.<br />By default Tailscale Kubernetes operator does not apply any resource<br />requirements. The amount of resources required wil depend on the<br />amount of resources the operator needs to parse, usage patterns and<br />cluster size.<br />https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#resources |  |  |
| `securityContext` _[SecurityContext](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.3/#securitycontext-v1-core)_ | Container security context.<br />Security context specified here will override the security context set by the operator.<br />By default the operator sets the Tailscale container and the Tailscale init container to privileged<br />for proxies created for Tailscale ingress and egress Service, Connector and ProxyGroup.<br />You can reduce the permissions of the Tailscale container to cap NET_ADMIN by<br />installing device plugin in your cluster and configuring the proxies tun device to be created<br />by the device plugin, see  https://github.com/tailscale/tailscale/issues/10814#issuecomment-2479977752<br />https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#security-context |  |  |
| `debug` _[Debug](#debug)_ | Configuration for enabling extra debug information in the container.<br />Not recommended for production use. |  |  |


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


#### Debug







_Appears in:_
- [Container](#container)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `enable` _boolean_ | Enable tailscaled's HTTP pprof endpoints at <pod-ip>:9001/debug/pprof/<br />and internal debug metrics endpoint at <pod-ip>:9001/debug/metrics, where<br />9001 is a container port named "debug". The endpoints and their responses<br />may change in backwards incompatible ways in the future, and should not<br />be considered stable.<br />In 1.78.x and 1.80.x, this setting will default to the value of<br />.spec.metrics.enable, and requests to the "metrics" port matching the<br />mux pattern /debug/ will be forwarded to the "debug" port. In 1.82.x,<br />this setting will default to false, and no requests will be proxied. |  |  |


#### Env







_Appears in:_
- [Container](#container)
- [RecorderContainer](#recordercontainer)

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



#### HostnamePrefix

_Underlying type:_ _string_



_Validation:_
- Pattern: `^[a-z0-9][a-z0-9-]{0,61}$`
- Type: string

_Appears in:_
- [ConnectorSpec](#connectorspec)
- [ProxyGroupSpec](#proxygroupspec)



#### KubeAPIServerConfig



KubeAPIServerConfig contains configuration specific to the kube-apiserver ProxyGroup type.



_Appears in:_
- [ProxyGroupSpec](#proxygroupspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `mode` _[APIServerProxyMode](#apiserverproxymode)_ | Mode to run the API server proxy in. Supported modes are auth and noauth.<br />In auth mode, requests from the tailnet proxied over to the Kubernetes<br />API server are additionally impersonated using the sender's tailnet identity.<br />If not specified, defaults to auth mode. |  | Enum: [auth noauth] <br />Type: string <br /> |
| `hostname` _string_ | Hostname is the hostname with which to expose the Kubernetes API server<br />proxies. Must be a valid DNS label no longer than 63 characters. If not<br />specified, the name of the ProxyGroup is used as the hostname. Must be<br />unique across the whole tailnet. |  | Pattern: `^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$` <br />Type: string <br /> |


#### LabelValue

_Underlying type:_ _string_



_Validation:_
- MaxLength: 63
- Pattern: `^(([a-zA-Z0-9][-._a-zA-Z0-9]*)?[a-zA-Z0-9])?$`
- Type: string

_Appears in:_
- [Labels](#labels)



#### Labels

_Underlying type:_ _[map[string]LabelValue](#map[string]labelvalue)_





_Appears in:_
- [Pod](#pod)
- [ServiceMonitor](#servicemonitor)
- [StatefulSet](#statefulset)



#### Metrics







_Appears in:_
- [ProxyClassSpec](#proxyclassspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `enable` _boolean_ | Setting enable to true will make the proxy serve Tailscale metrics<br />at <pod-ip>:9002/metrics.<br />A metrics Service named <proxy-statefulset>-metrics will also be created in the operator's namespace and will<br />serve the metrics at <service-ip>:9002/metrics.<br />In 1.78.x and 1.80.x, this field also serves as the default value for<br />.spec.statefulSet.pod.tailscaleContainer.debug.enable. From 1.82.0, both<br />fields will independently default to false.<br />Defaults to false. |  |  |
| `serviceMonitor` _[ServiceMonitor](#servicemonitor)_ | Enable to create a Prometheus ServiceMonitor for scraping the proxy's Tailscale metrics.<br />The ServiceMonitor will select the metrics Service that gets created when metrics are enabled.<br />The ingested metrics for each Service monitor will have labels to identify the proxy:<br />ts_proxy_type: ingress_service\|ingress_resource\|connector\|proxygroup<br />ts_proxy_parent_name: name of the parent resource (i.e name of the Connector, Tailscale Ingress, Tailscale Service or ProxyGroup)<br />ts_proxy_parent_namespace: namespace of the parent resource (if the parent resource is not cluster scoped)<br />job: ts_<proxy type>_[<parent namespace>]_<parent_name> |  |  |


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
| `image` _[NameserverImage](#nameserverimage)_ | Nameserver image. Defaults to tailscale/k8s-nameserver:unstable. |  |  |
| `service` _[NameserverService](#nameserverservice)_ | Service configuration. |  |  |
| `replicas` _integer_ | Replicas specifies how many Pods to create. Defaults to 1. |  | Minimum: 0 <br /> |


#### NameserverImage







_Appears in:_
- [Nameserver](#nameserver)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `repo` _string_ | Repo defaults to tailscale/k8s-nameserver. |  |  |
| `tag` _string_ | Tag defaults to unstable. |  |  |


#### NameserverService







_Appears in:_
- [Nameserver](#nameserver)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `clusterIP` _string_ | ClusterIP sets the static IP of the service used by the nameserver. |  |  |


#### NameserverStatus







_Appears in:_
- [DNSConfigStatus](#dnsconfigstatus)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `ip` _string_ | IP is the ClusterIP of the Service fronting the deployed ts.net nameserver.<br />Currently, you must manually update your cluster DNS config to add<br />this address as a stub nameserver for ts.net for cluster workloads to be<br />able to resolve MagicDNS names associated with egress or Ingress<br />proxies.<br />The IP address will change if you delete and recreate the DNSConfig. |  |  |


#### NodePortConfig







_Appears in:_
- [StaticEndpointsConfig](#staticendpointsconfig)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `ports` _[PortRange](#portrange) array_ | The port ranges from which the operator will select NodePorts for the Services.<br />You must ensure that firewall rules allow UDP ingress traffic for these ports<br />to the node's external IPs.<br />The ports must be in the range of service node ports for the cluster (default `30000-32767`).<br />See https://kubernetes.io/docs/concepts/services-networking/service/#type-nodeport. |  | MinItems: 1 <br /> |
| `selector` _object (keys:string, values:string)_ | A selector which will be used to select the node's that will have their `ExternalIP`'s advertised<br />by the ProxyGroup as Static Endpoints. |  |  |


#### Pod







_Appears in:_
- [StatefulSet](#statefulset)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `labels` _[Labels](#labels)_ | Labels that will be added to the proxy Pod.<br />Any labels specified here will be merged with the default labels<br />applied to the Pod by the Tailscale Kubernetes operator.<br />Label keys and values must be valid Kubernetes label keys and values.<br />https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#syntax-and-character-set |  |  |
| `annotations` _object (keys:string, values:string)_ | Annotations that will be added to the proxy Pod.<br />Any annotations specified here will be merged with the default<br />annotations applied to the Pod by the Tailscale Kubernetes operator.<br />Annotations must be valid Kubernetes annotations.<br />https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/#syntax-and-character-set |  |  |
| `affinity` _[Affinity](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.3/#affinity-v1-core)_ | Proxy Pod's affinity rules.<br />By default, the Tailscale Kubernetes operator does not apply any affinity rules.<br />https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#affinity |  |  |
| `tailscaleContainer` _[Container](#container)_ | Configuration for the proxy container running tailscale. |  |  |
| `tailscaleInitContainer` _[Container](#container)_ | Configuration for the proxy init container that enables forwarding.<br />Not valid to apply to ProxyGroups of type "kube-apiserver". |  |  |
| `securityContext` _[PodSecurityContext](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.3/#podsecuritycontext-v1-core)_ | Proxy Pod's security context.<br />By default Tailscale Kubernetes operator does not apply any Pod<br />security context.<br />https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#security-context-2 |  |  |
| `imagePullSecrets` _[LocalObjectReference](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.3/#localobjectreference-v1-core) array_ | Proxy Pod's image pull Secrets.<br />https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#PodSpec |  |  |
| `nodeName` _string_ | Proxy Pod's node name.<br />https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#scheduling |  |  |
| `nodeSelector` _object (keys:string, values:string)_ | Proxy Pod's node selector.<br />By default Tailscale Kubernetes operator does not apply any node<br />selector.<br />https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#scheduling |  |  |
| `tolerations` _[Toleration](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.3/#toleration-v1-core) array_ | Proxy Pod's tolerations.<br />By default Tailscale Kubernetes operator does not apply any<br />tolerations.<br />https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#scheduling |  |  |
| `topologySpreadConstraints` _[TopologySpreadConstraint](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.3/#topologyspreadconstraint-v1-core) array_ | Proxy Pod's topology spread constraints.<br />By default Tailscale Kubernetes operator does not apply any topology spread constraints.<br />https://kubernetes.io/docs/concepts/scheduling-eviction/topology-spread-constraints/ |  |  |
| `priorityClassName` _string_ | PriorityClassName for the proxy Pod.<br />By default Tailscale Kubernetes operator does not apply any priority class.<br />https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#scheduling |  |  |


#### PortRange







_Appears in:_
- [NodePortConfig](#nodeportconfig)
- [PortRanges](#portranges)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `port` _integer_ | port represents a port selected to be used. This is a required field. |  |  |
| `endPort` _integer_ | endPort indicates that the range of ports from port to endPort if set, inclusive,<br />should be used. This field cannot be defined if the port field is not defined.<br />The endPort must be either unset, or equal or greater than port. |  |  |




#### ProxyClass



ProxyClass describes a set of configuration parameters that can be applied to
proxy resources created by the Tailscale Kubernetes operator.
To apply a given ProxyClass to resources created for a tailscale Ingress or
Service, use tailscale.com/proxy-class=<proxyclass-name> label. To apply a
given ProxyClass to resources created for a Connector, use
connector.spec.proxyClass field.
ProxyClass is a cluster scoped resource.
More info:
https://tailscale.com/kb/1445/kubernetes-operator-customization#cluster-resource-customization-using-proxyclass-custom-resource



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
| `useLetsEncryptStagingEnvironment` _boolean_ | Set UseLetsEncryptStagingEnvironment to true to issue TLS<br />certificates for any HTTPS endpoints exposed to the tailnet from<br />LetsEncrypt's staging environment.<br />https://letsencrypt.org/docs/staging-environment/<br />This setting only affects Tailscale Ingress resources.<br />By default Ingress TLS certificates are issued from LetsEncrypt's<br />production environment.<br />Changing this setting true -> false, will result in any<br />existing certs being re-issued from the production environment.<br />Changing this setting false (default) -> true, when certs have already<br />been provisioned from production environment will NOT result in certs<br />being re-issued from the staging environment before they need to be<br />renewed. |  |  |
| `staticEndpoints` _[StaticEndpointsConfig](#staticendpointsconfig)_ | Configuration for 'static endpoints' on proxies in order to facilitate<br />direct connections from other devices on the tailnet.<br />See https://tailscale.com/kb/1445/kubernetes-operator-customization#static-endpoints. |  |  |


#### ProxyClassStatus







_Appears in:_
- [ProxyClass](#proxyclass)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.3/#condition-v1-meta) array_ | List of status conditions to indicate the status of the ProxyClass.<br />Known condition types are `ProxyClassReady`. |  |  |


#### ProxyGroup



ProxyGroup defines a set of Tailscale devices that will act as proxies.
Depending on spec.Type, it can be a group of egress, ingress, or kube-apiserver
proxies. In addition to running a highly available set of proxies, ingress
and egress ProxyGroups also allow for serving many annotated Services from a
single set of proxies to minimise resource consumption.

For ingress and egress, use the tailscale.com/proxy-group annotation on a
Service to specify that the proxy should be implemented by a ProxyGroup
instead of a single dedicated proxy.

More info:
* https://tailscale.com/kb/1438/kubernetes-operator-cluster-egress
* https://tailscale.com/kb/1439/kubernetes-operator-cluster-ingress

For kube-apiserver, the ProxyGroup is a standalone resource. Use the
spec.kubeAPIServer field to configure options specific to the kube-apiserver
ProxyGroup type.



_Appears in:_
- [ProxyGroupList](#proxygrouplist)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `tailscale.com/v1alpha1` | | |
| `kind` _string_ | `ProxyGroup` | | |
| `kind` _string_ | Kind is a string value representing the REST resource this object represents.<br />Servers may infer this from the endpoint the client submits requests to.<br />Cannot be updated.<br />In CamelCase.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds |  |  |
| `apiVersion` _string_ | APIVersion defines the versioned schema of this representation of an object.<br />Servers should convert recognized schemas to the latest internal value, and<br />may reject unrecognized values.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources |  |  |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.3/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[ProxyGroupSpec](#proxygroupspec)_ | Spec describes the desired ProxyGroup instances. |  |  |
| `status` _[ProxyGroupStatus](#proxygroupstatus)_ | ProxyGroupStatus describes the status of the ProxyGroup resources. This is<br />set and managed by the Tailscale operator. |  |  |


#### ProxyGroupList









| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `tailscale.com/v1alpha1` | | |
| `kind` _string_ | `ProxyGroupList` | | |
| `kind` _string_ | Kind is a string value representing the REST resource this object represents.<br />Servers may infer this from the endpoint the client submits requests to.<br />Cannot be updated.<br />In CamelCase.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds |  |  |
| `apiVersion` _string_ | APIVersion defines the versioned schema of this representation of an object.<br />Servers should convert recognized schemas to the latest internal value, and<br />may reject unrecognized values.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources |  |  |
| `metadata` _[ListMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.3/#listmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `items` _[ProxyGroup](#proxygroup) array_ |  |  |  |


#### ProxyGroupSpec







_Appears in:_
- [ProxyGroup](#proxygroup)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `type` _[ProxyGroupType](#proxygrouptype)_ | Type of the ProxyGroup proxies. Supported types are egress, ingress, and kube-apiserver.<br />Type is immutable once a ProxyGroup is created. |  | Enum: [egress ingress kube-apiserver] <br />Type: string <br /> |
| `tags` _[Tags](#tags)_ | Tags that the Tailscale devices will be tagged with. Defaults to [tag:k8s].<br />If you specify custom tags here, make sure you also make the operator<br />an owner of these tags.<br />See  https://tailscale.com/kb/1236/kubernetes-operator/#setting-up-the-kubernetes-operator.<br />Tags cannot be changed once a ProxyGroup device has been created.<br />Tag values must be in form ^tag:[a-zA-Z][a-zA-Z0-9-]*$. |  | Pattern: `^tag:[a-zA-Z][a-zA-Z0-9-]*$` <br />Type: string <br /> |
| `replicas` _integer_ | Replicas specifies how many replicas to create the StatefulSet with.<br />Defaults to 2. |  | Minimum: 0 <br /> |
| `hostnamePrefix` _[HostnamePrefix](#hostnameprefix)_ | HostnamePrefix is the hostname prefix to use for tailnet devices created<br />by the ProxyGroup. Each device will have the integer number from its<br />StatefulSet pod appended to this prefix to form the full hostname.<br />HostnamePrefix can contain lower case letters, numbers and dashes, it<br />must not start with a dash and must be between 1 and 62 characters long. |  | Pattern: `^[a-z0-9][a-z0-9-]{0,61}$` <br />Type: string <br /> |
| `proxyClass` _string_ | ProxyClass is the name of the ProxyClass custom resource that contains<br />configuration options that should be applied to the resources created<br />for this ProxyGroup. If unset, and there is no default ProxyClass<br />configured, the operator will create resources with the default<br />configuration. |  |  |
| `kubeAPIServer` _[KubeAPIServerConfig](#kubeapiserverconfig)_ | KubeAPIServer contains configuration specific to the kube-apiserver<br />ProxyGroup type. This field is only used when Type is set to "kube-apiserver". |  |  |


#### ProxyGroupStatus







_Appears in:_
- [ProxyGroup](#proxygroup)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.3/#condition-v1-meta) array_ | List of status conditions to indicate the status of the ProxyGroup<br />resources. Known condition types include `ProxyGroupReady` and<br />`ProxyGroupAvailable`.<br />* `ProxyGroupReady` indicates all ProxyGroup resources are reconciled and<br />  all expected conditions are true.<br />* `ProxyGroupAvailable` indicates that at least one proxy is ready to<br />  serve traffic.<br />For ProxyGroups of type kube-apiserver, there are two additional conditions:<br />* `KubeAPIServerProxyConfigured` indicates that at least one API server<br />  proxy is configured and ready to serve traffic.<br />* `KubeAPIServerProxyValid` indicates that spec.kubeAPIServer config is<br />  valid. |  |  |
| `devices` _[TailnetDevice](#tailnetdevice) array_ | List of tailnet devices associated with the ProxyGroup StatefulSet. |  |  |
| `url` _string_ | URL of the kube-apiserver proxy advertised by the ProxyGroup devices, if<br />any. Only applies to ProxyGroups of type kube-apiserver. |  |  |


#### ProxyGroupType

_Underlying type:_ _string_



_Validation:_
- Enum: [egress ingress kube-apiserver]
- Type: string

_Appears in:_
- [ProxyGroupSpec](#proxygroupspec)



#### Recorder



Recorder defines a tsrecorder device for recording SSH sessions. By default,
it will store recordings in a local ephemeral volume. If you want to persist
recordings, you can configure an S3-compatible API for storage.

More info: https://tailscale.com/kb/1484/kubernetes-operator-deploying-tsrecorder



_Appears in:_
- [RecorderList](#recorderlist)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `tailscale.com/v1alpha1` | | |
| `kind` _string_ | `Recorder` | | |
| `kind` _string_ | Kind is a string value representing the REST resource this object represents.<br />Servers may infer this from the endpoint the client submits requests to.<br />Cannot be updated.<br />In CamelCase.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds |  |  |
| `apiVersion` _string_ | APIVersion defines the versioned schema of this representation of an object.<br />Servers should convert recognized schemas to the latest internal value, and<br />may reject unrecognized values.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources |  |  |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.3/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[RecorderSpec](#recorderspec)_ | Spec describes the desired recorder instance. |  |  |
| `status` _[RecorderStatus](#recorderstatus)_ | RecorderStatus describes the status of the recorder. This is set<br />and managed by the Tailscale operator. |  |  |


#### RecorderContainer







_Appears in:_
- [RecorderPod](#recorderpod)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `env` _[Env](#env) array_ | List of environment variables to set in the container.<br />https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#environment-variables<br />Note that environment variables provided here will take precedence<br />over Tailscale-specific environment variables set by the operator,<br />however running proxies with custom values for Tailscale environment<br />variables (i.e TS_USERSPACE) is not recommended and might break in<br />the future. |  |  |
| `image` _string_ | Container image name including tag. Defaults to docker.io/tailscale/tsrecorder<br />with the same tag as the operator, but the official images are also<br />available at ghcr.io/tailscale/tsrecorder.<br />https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#image |  |  |
| `imagePullPolicy` _[PullPolicy](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.3/#pullpolicy-v1-core)_ | Image pull policy. One of Always, Never, IfNotPresent. Defaults to Always.<br />https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#image |  | Enum: [Always Never IfNotPresent] <br /> |
| `resources` _[ResourceRequirements](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.3/#resourcerequirements-v1-core)_ | Container resource requirements.<br />By default, the operator does not apply any resource requirements. The<br />amount of resources required wil depend on the volume of recordings sent.<br />https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#resources |  |  |
| `securityContext` _[SecurityContext](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.3/#securitycontext-v1-core)_ | Container security context. By default, the operator does not apply any<br />container security context.<br />https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#security-context |  |  |


#### RecorderList









| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `tailscale.com/v1alpha1` | | |
| `kind` _string_ | `RecorderList` | | |
| `kind` _string_ | Kind is a string value representing the REST resource this object represents.<br />Servers may infer this from the endpoint the client submits requests to.<br />Cannot be updated.<br />In CamelCase.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds |  |  |
| `apiVersion` _string_ | APIVersion defines the versioned schema of this representation of an object.<br />Servers should convert recognized schemas to the latest internal value, and<br />may reject unrecognized values.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources |  |  |
| `metadata` _[ListMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.3/#listmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `items` _[Recorder](#recorder) array_ |  |  |  |


#### RecorderPod







_Appears in:_
- [RecorderStatefulSet](#recorderstatefulset)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `labels` _object (keys:string, values:string)_ | Labels that will be added to Recorder Pods. Any labels specified here<br />will be merged with the default labels applied to the Pod by the operator.<br />https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#syntax-and-character-set |  |  |
| `annotations` _object (keys:string, values:string)_ | Annotations that will be added to Recorder Pods. Any annotations<br />specified here will be merged with the default annotations applied to<br />the Pod by the operator.<br />https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/#syntax-and-character-set |  |  |
| `affinity` _[Affinity](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.3/#affinity-v1-core)_ | Affinity rules for Recorder Pods. By default, the operator does not<br />apply any affinity rules.<br />https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#affinity |  |  |
| `container` _[RecorderContainer](#recordercontainer)_ | Configuration for the Recorder container running tailscale. |  |  |
| `securityContext` _[PodSecurityContext](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.3/#podsecuritycontext-v1-core)_ | Security context for Recorder Pods. By default, the operator does not<br />apply any Pod security context.<br />https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#security-context-2 |  |  |
| `imagePullSecrets` _[LocalObjectReference](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.3/#localobjectreference-v1-core) array_ | Image pull Secrets for Recorder Pods.<br />https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#PodSpec |  |  |
| `nodeSelector` _object (keys:string, values:string)_ | Node selector rules for Recorder Pods. By default, the operator does<br />not apply any node selector rules.<br />https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#scheduling |  |  |
| `tolerations` _[Toleration](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.3/#toleration-v1-core) array_ | Tolerations for Recorder Pods. By default, the operator does not apply<br />any tolerations.<br />https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#scheduling |  |  |
| `serviceAccount` _[RecorderServiceAccount](#recorderserviceaccount)_ | Config for the ServiceAccount to create for the Recorder's StatefulSet.<br />By default, the operator will create a ServiceAccount with the same<br />name as the Recorder resource.<br />https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#service-account |  |  |


#### RecorderServiceAccount







_Appears in:_
- [RecorderPod](#recorderpod)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ | Name of the ServiceAccount to create. Defaults to the name of the<br />Recorder resource.<br />https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#service-account |  | MaxLength: 253 <br />Pattern: `^[a-z0-9]([a-z0-9-.]{0,61}[a-z0-9])?$` <br />Type: string <br /> |
| `annotations` _object (keys:string, values:string)_ | Annotations to add to the ServiceAccount.<br />https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/#syntax-and-character-set<br />You can use this to add IAM roles to the ServiceAccount (IRSA) instead of<br />providing static S3 credentials in a Secret.<br />https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html<br />For example:<br />eks.amazonaws.com/role-arn: arn:aws:iam::<account-id>:role/<role-name> |  |  |


#### RecorderSpec







_Appears in:_
- [Recorder](#recorder)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `statefulSet` _[RecorderStatefulSet](#recorderstatefulset)_ | Configuration parameters for the Recorder's StatefulSet. The operator<br />deploys a StatefulSet for each Recorder resource. |  |  |
| `tags` _[Tags](#tags)_ | Tags that the Tailscale device will be tagged with. Defaults to [tag:k8s].<br />If you specify custom tags here, make sure you also make the operator<br />an owner of these tags.<br />See  https://tailscale.com/kb/1236/kubernetes-operator/#setting-up-the-kubernetes-operator.<br />Tags cannot be changed once a Recorder node has been created.<br />Tag values must be in form ^tag:[a-zA-Z][a-zA-Z0-9-]*$. |  | Pattern: `^tag:[a-zA-Z][a-zA-Z0-9-]*$` <br />Type: string <br /> |
| `enableUI` _boolean_ | Set to true to enable the Recorder UI. The UI lists and plays recorded sessions.<br />The UI will be served at <MagicDNS name of the recorder>:443. Defaults to false.<br />Corresponds to --ui tsrecorder flag https://tailscale.com/kb/1246/tailscale-ssh-session-recording#deploy-a-recorder-node.<br />Required if S3 storage is not set up, to ensure that recordings are accessible. |  |  |
| `storage` _[Storage](#storage)_ | Configure where to store session recordings. By default, recordings will<br />be stored in a local ephemeral volume, and will not be persisted past the<br />lifetime of a specific pod. |  |  |


#### RecorderStatefulSet







_Appears in:_
- [RecorderSpec](#recorderspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `labels` _object (keys:string, values:string)_ | Labels that will be added to the StatefulSet created for the Recorder.<br />Any labels specified here will be merged with the default labels applied<br />to the StatefulSet by the operator.<br />https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#syntax-and-character-set |  |  |
| `annotations` _object (keys:string, values:string)_ | Annotations that will be added to the StatefulSet created for the Recorder.<br />Any Annotations specified here will be merged with the default annotations<br />applied to the StatefulSet by the operator.<br />https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/#syntax-and-character-set |  |  |
| `pod` _[RecorderPod](#recorderpod)_ | Configuration for pods created by the Recorder's StatefulSet. |  |  |


#### RecorderStatus







_Appears in:_
- [Recorder](#recorder)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.3/#condition-v1-meta) array_ | List of status conditions to indicate the status of the Recorder.<br />Known condition types are `RecorderReady`. |  |  |
| `devices` _[RecorderTailnetDevice](#recordertailnetdevice) array_ | List of tailnet devices associated with the Recorder StatefulSet. |  |  |


#### RecorderTailnetDevice







_Appears in:_
- [RecorderStatus](#recorderstatus)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `hostname` _string_ | Hostname is the fully qualified domain name of the device.<br />If MagicDNS is enabled in your tailnet, it is the MagicDNS name of the<br />node. |  |  |
| `tailnetIPs` _string array_ | TailnetIPs is the set of tailnet IP addresses (both IPv4 and IPv6)<br />assigned to the device. |  |  |
| `url` _string_ | URL where the UI is available if enabled for replaying recordings. This<br />will be an HTTPS MagicDNS URL. You must be connected to the same tailnet<br />as the recorder to access it. |  |  |


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
- [AppConnector](#appconnector)
- [SubnetRouter](#subnetrouter)



#### S3







_Appears in:_
- [Storage](#storage)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `endpoint` _string_ | S3-compatible endpoint, e.g. s3.us-east-1.amazonaws.com. |  |  |
| `bucket` _string_ | Bucket name to write to. The bucket is expected to be used solely for<br />recordings, as there is no stable prefix for written object names. |  |  |
| `credentials` _[S3Credentials](#s3credentials)_ | Configure environment variable credentials for managing objects in the<br />configured bucket. If not set, tsrecorder will try to acquire credentials<br />first from the file system and then the STS API. |  |  |


#### S3Credentials







_Appears in:_
- [S3](#s3)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `secret` _[S3Secret](#s3secret)_ | Use a Kubernetes Secret from the operator's namespace as the source of<br />credentials. |  |  |


#### S3Secret







_Appears in:_
- [S3Credentials](#s3credentials)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ | The name of a Kubernetes Secret in the operator's namespace that contains<br />credentials for writing to the configured bucket. Each key-value pair<br />from the secret's data will be mounted as an environment variable. It<br />should include keys for AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY if<br />using a static access key. |  |  |


#### ServiceMonitor







_Appears in:_
- [Metrics](#metrics)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `enable` _boolean_ | If Enable is set to true, a Prometheus ServiceMonitor will be created. Enable can only be set to true if metrics are enabled. |  |  |
| `labels` _[Labels](#labels)_ | Labels to add to the ServiceMonitor.<br />Labels must be valid Kubernetes labels.<br />https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#syntax-and-character-set |  |  |


#### StatefulSet







_Appears in:_
- [ProxyClassSpec](#proxyclassspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `labels` _[Labels](#labels)_ | Labels that will be added to the StatefulSet created for the proxy.<br />Any labels specified here will be merged with the default labels<br />applied to the StatefulSet by the Tailscale Kubernetes operator as<br />well as any other labels that might have been applied by other<br />actors.<br />Label keys and values must be valid Kubernetes label keys and values.<br />https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#syntax-and-character-set |  |  |
| `annotations` _object (keys:string, values:string)_ | Annotations that will be added to the StatefulSet created for the proxy.<br />Any Annotations specified here will be merged with the default annotations<br />applied to the StatefulSet by the Tailscale Kubernetes operator as<br />well as any other annotations that might have been applied by other<br />actors.<br />Annotations must be valid Kubernetes annotations.<br />https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/#syntax-and-character-set |  |  |
| `pod` _[Pod](#pod)_ | Configuration for the proxy Pod. |  |  |


#### StaticEndpointsConfig







_Appears in:_
- [ProxyClassSpec](#proxyclassspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `nodePort` _[NodePortConfig](#nodeportconfig)_ | The configuration for static endpoints using NodePort Services. |  |  |


#### Storage







_Appears in:_
- [RecorderSpec](#recorderspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `s3` _[S3](#s3)_ | Configure an S3-compatible API for storage. Required if the UI is not<br />enabled, to ensure that recordings are accessible. |  |  |


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
- [ProxyGroupSpec](#proxygroupspec)
- [RecorderSpec](#recorderspec)



#### TailnetDevice







_Appears in:_
- [ProxyGroupStatus](#proxygroupstatus)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `hostname` _string_ | Hostname is the fully qualified domain name of the device.<br />If MagicDNS is enabled in your tailnet, it is the MagicDNS name of the<br />node. |  |  |
| `tailnetIPs` _string array_ | TailnetIPs is the set of tailnet IP addresses (both IPv4 and IPv6)<br />assigned to the device. |  |  |
| `staticEndpoints` _string array_ | StaticEndpoints are user configured, 'static' endpoints by which tailnet peers can reach this device. |  |  |


#### TailscaleConfig







_Appears in:_
- [ProxyClassSpec](#proxyclassspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `acceptRoutes` _boolean_ | AcceptRoutes can be set to true to make the proxy instance accept<br />routes advertized by other nodes on the tailnet, such as subnet<br />routes.<br />This is equivalent of passing --accept-routes flag to a tailscale Linux client.<br />https://tailscale.com/kb/1019/subnets#use-your-subnet-routes-from-other-devices<br />Defaults to false. |  |  |


