### checkout this branch
```
mkdir -p $HOME/tailscale/{branch_name} && cd $HOME/tailscale/{branch_name}
git init && git remote add origin https://github.com/tailscale/tailscale.git
git fetch origin --tags && git fetch origin pull/{pull_id}/head:{branch_name}
git checkout {branch_name}
``` 

