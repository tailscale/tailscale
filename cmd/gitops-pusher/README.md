# gitops-pusher

This is a small tool to help people achieve a
[GitOps](https://about.gitlab.com/topics/gitops/) workflow with Tailscale ACL
changes. This tool is intended to be used in a CI flow that looks like this:

```yaml
name: Tailscale ACL syncing

on:
  push:
    branches: [ "main" ]
  pull_request:
    branches: [ "main" ]

jobs:
  acls:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Go environment
        uses: actions/setup-go@v3.2.0
        
      - name: Install gitops-pusher
        run: go install tailscale.com/cmd/gitops-pusher@latest
              
      - name: Deploy ACL
        if: github.event_name == 'push'
        env:
          TS_API_KEY: ${{ secrets.TS_API_KEY }}
          TS_TAILNET: ${{ secrets.TS_TAILNET }}
        run: |
          ~/go/bin/gitops-pusher --policy-file ./policy.hujson apply

      - name: ACL tests
        if: github.event_name == 'pull_request'
        env:
          TS_API_KEY: ${{ secrets.TS_API_KEY }}
          TS_TAILNET: ${{ secrets.TS_TAILNET }}
        run: |
          ~/go/bin/gitops-pusher --policy-file ./policy.hujson test
```

Change the value of the `--policy-file` flag to point to the policy file on
disk. Policy files should be in [HuJSON](https://github.com/tailscale/hujson)
format.
