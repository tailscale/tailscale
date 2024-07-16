eks-nlb can be used to set up routing from an AWS NLB to wireguard port of Tailscale running in a Pod.

### Pods must:

- have tailscale.com/enlb-configmap annotation set to a ConfigMap that contains NLB ARN and the ID of the EKS cluster VPC
(see structure in example.yamls)

- have TS_DEBUG_PRETENDPOINT env var set directly on 'tailscale' container config or provided via ConfigMap

- have a container named 'tailscale' that runs tailscale

- have wireguard port set to 41641

- have metrics exposed on port 9001 (temporary health check solution)

## Deploy

Deploy (in default namespace):

1. Create a Secret with AWS creds 

```sh
kubectl create secret generic aws-creds --from-literal aws_access_key_id=<AWS_ACCESS_KEY_ID> \
--from-literal aws_secret_access_key=<AWS_SECRET_ACCESS_KEY>
```

2. (Optional) Modify image in ./deploy.yaml

3. Deploy:

```
$ kubectl apply -f ./deploy.yaml
```

## Usage example

See an example manifest in ./example.yaml

To use:
- deploy the controller
- create an NLB load balancer, set up security groups etc
- create a Secret with tailscale auth key
```
kubectl create secret generic ts-creds --from-literal=authkey=<ts-auth-key>
```
- populate 'eks-config' ConfigMap with NLB ARN and the VPC of the EKS cluster

- poulate 'pretendpoint' ConfigMap with pairs of load balancer external IPs + port 


For this, eks-nlb will ensure that the single replica is exposed on the port specified in via TS_DEBUG_PRETENDPOINT env var read from 'pretendpoint' ConfigMap on the load balancer whose ARN is passed via tailscale.com/awsnlbarn annotation to the StatefulSet.

TODO: this flow is inconvenient. We should be able to make eks-nlb dynamically set TS_DEBUG_PRETENDPOINT once we can have tailscaled dynamically reloading its config. 

The controller will:

- create a target group with the Pod IP routing traffic to 41641 and using 9001 as health check port

- expose this target on the NLB via the port parsed from TS_DEBUG_PRETENDPOINT

## Dev

Build and push images with `REPO="<registry>/eksnlb" TAGS=<tags> make publishdeveksnlb`
