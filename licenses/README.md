# Licenses

This directory contains a list of dependencies, and their licenses, that are included in the Tailscale clients.
These lists are generated using the [go-licenses] tool to analyze all Go packages in the Tailscale binaries,
as well as a set of custom output templates that includes any additional non-Go dependencies.
For example, the clients for macOS and iOS include some additional Swift libraries.

These lists are updated roughly every week, so it is possible to see the dependencies in a given release by looking at the release tag.
For example, the dependences for the 1.80.0 release of the macOS client can be seen at
<https://github.com/tailscale/tailscale/blob/v1.80.0/licenses/apple.md>.

[go-licenses]: https://github.com/google/go-licenses

## Other formats

The go-licenses tool can output other formats like CSV, but that wouldn't include the non-Go dependencies.
We can generate a CSV file if that's really needed by running a regex over the markdown files:

```sh
cat apple.md | grep "^ -" | sed -E "s/- \[(.*)\]\(.*?\) \(\[(.*)\]\((.*)\)\)/\1,\2,\3/"
```

## Reviewer instructions

The majority of changes in this directory are from updating dependency versions.
In that case, only the URL for the license file will change to reflect the new version.
Occasionally, a dependency is added or removed, or the import path is changed.

New dependencies require the closest review to ensure the license is acceptable.
Because we generate the license reports **after** dependencies are changed,
the new dependency would have already gone through one review when it was initially added.
This is just a secondary review to double-check the license. If in doubt, ask legal.

Always do a normal GitHub code review on the license PR with a brief summary of what changed.
For example, see #13936 or #14064. Then approve and merge the PR.
