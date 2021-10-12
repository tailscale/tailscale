# Overview
There are quite a few ways of running Tailscale inside a Kubernetes Cluster, some of the common ones are covered in this doc.
## Instructions
### Setup
1. (Optional) Create the following secret which will automate login.<br>
   You will need to get an [auth key](https://tailscale.com/kb/1085/auth-keys/) from [Tailscale Admin Console](https://login.tailscale.com/admin/authkeys).<br>
   If you don't provide the key, you can still authenticate using the url in the logs.

   ```yaml
   apiVersion: v1
   kind: Secret
   metadata:
     name: tailscale-auth
   stringData:
     AUTH_KEY: tskey-...
   ```

1. Build and push the container

   ```bash
   export IMAGE_TAG=tailscale-k8s:latest
   make push
   ```

1. Tailscale (v1.16+) supports storing state inside a Kubernetes Secret.

   Configure RBAC to allow the Tailscale pod to read/write the `tailscale` secret.
   ```bash
   export SA_NAME=tailscale
   export KUBE_SECRET=tailscale
   make rbac
   ```

### Sample Sidecar
Running as a sidecar allows you to directly expose a Kubernetes pod over Tailscale. This is particularly useful if you do not wish to expose a service on the public internet. This method allows bi-directional connectivty between the pod and other devices on the Tailnet. You can use [ACLs](https://tailscale.com/kb/1018/acls/) to control traffic flow.

1. Create and login to the sample nginx pod with a Tailscale sidecar

   ```bash
   make sidecar
   # If not using an auth key, authenticate by grabbing the Login URL here:
   kubectl logs nginx ts-sidecar
   ```

1. Check if you can to connect to nginx over Tailscale:

   ```bash
   curl http://nginx
   ```
   Or, if you have [MagicDNS](https://tailscale.com/kb/1081/magicdns/) disabled:
   ```bash
   curl "http://$(tailscale ip -4 nginx)"
   ```

#### Userspace Sidecar
You can also run the sidecar in userspace mode. The obvious benefit is reducing the amount of permissions Tailscale needs to run, the downside is that for outbound connectivity from the pod to the Tailnet you would need to use either the [SOCKS proxy](https://tailscale.com/kb/1112/userspace-networking) or HTTP proxy.

1. Create and login to the sample nginx pod with a Tailscale sidecar

   ```bash
   make userspace-sidecar
   # If not using an auth key, authenticate by grabbing the Login URL here:
   kubectl logs nginx ts-sidecar
   ```

1. Check if you can to connect to nginx over Tailscale:

   ```bash
   curl http://nginx
   ```
   Or, if you have [MagicDNS](https://tailscale.com/kb/1081/magicdns/) disabled:
   ```bash
   curl "http://$(tailscale ip -4 nginx)"
   ```

### Sample Proxy
Running a Tailscale proxy allows you to provide inbound connectivity to a Kubernetes Service.

1. Provide the `ClusterIP` of the service you want to reach by either:

   **Creating a new deployment**
   ```bash
   kubectl create deployment nginx --image nginx
   kubectl expose deployment nginx --port 80
   export DEST_IP="$(kubectl get svc nginx -o=jsonpath='{.spec.clusterIP}')"
   ```
   **Using an existing service**
   ```bash
   export DEST_IP="$(kubectl get svc <SVC_NAME> -o=jsonpath='{.spec.clusterIP}')"
   ```

1. Deploy the proxy pod

   ```bash
   make proxy
   # If not using an auth key, authenticate by grabbing the Login URL here:
   kubectl logs proxy
   ```

1. Check if you can to connect to nginx over Tailscale:

   ```bash
   curl http://proxy
   ```

   Or, if you have [MagicDNS](https://tailscale.com/kb/1081/magicdns/) disabled:

   ```bash
   curl "http://$(tailscale ip -4 proxy)"
   ```