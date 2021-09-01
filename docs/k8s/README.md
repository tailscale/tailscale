# Using Kubernetes Secrets as the state store for Tailscale
Tailscale supports using Kubernetes Secrets as the state store, however there is some configuration required in order for it to work.

**Note: this only works if `tailscaled` runs inside a pod in the cluster.**

1. Create a service account for Tailscale (optional)
   ```
   kubectl create -f sa.yaml
   ```

1. Create role and role bindings for the service account
   ```
   kubectl create -f role.yaml
   kubectl create -f rolebinding.yaml
   ```

1. Launch `tailscaled` with a Kubernetes Secret as the state store.
   ```
   tailscaled --state=kube:tailscale
   ```
