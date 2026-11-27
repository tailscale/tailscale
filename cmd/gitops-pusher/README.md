# gitops-pusher

This is a small tool to help people achieve a
[GitOps](https://about.gitlab.com/topics/gitops/) workflow with Tailscale ACL
changes. This tool is intended to be used in a CI flow that looks like this:

See [gitops-acl-action](https://github.com/tailscale/gitops-acl-action/blob/main/README.md)
for instructions how to use this with GitHub Actions.

Change the value of the `--policy-file` flag to point to the policy file on
disk. Policy files should be in [HuJSON](https://github.com/tailscale/hujson)
format.
