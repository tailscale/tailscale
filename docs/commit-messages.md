# Commit messages

There are different styles of commit messages followed by different projects.
This is Tailscale's style guide for writing git commit messages.
As with all style guides, many things here are subjective and exist primarily to
codify existing conventions and promote uniformity and thus ease of reading by
others. Others have stronger reasons, such as interop with tooling or making
future git archaeology easier.

Our commit message style is largely based on the Go language's style, which
shares much in common with the Linux kernel's git commit message style (for
which git was invented):

* Go's high-level example: https://go.dev/doc/contribute#commit_messages
* Go's details: https://golang.org/wiki/CommitMessage
* Linux's style: https://www.kernel.org/doc/html/v4.10/process/submitting-patches.html#describe-your-changes

(We do *not* use the [Conventional
Commits](https://www.conventionalcommits.org/en/v1.0.0/) style or [Semantic
Commits](https://gist.github.com/joshbuchea/6f47e86d2510bce28f8e7f42ae84c716)
styles. They're reasonable, but we have already been using the Go and Linux
style of commit messages and there is little justification for switching styles.
Consistency is valuable.)

In a nutshell, our commit messages should look like:

```
net/http: handle foo when bar

[longer description here in the body]

Fixes #nnnn
```

Notably, for the subject (the first line of description):

- the primary director(ies) from the root affected by the change goes before the colon, e.g. “derp/derphttp:” (if a lot of packages are involved, you can abbreviate to top-level names e.g. ”derp,magicsock:”, and/or remove less relevant packages)
- the part after the colon is a verb, ideally an imperative verb (Linux style, telling the code what to do) or alternatively an infinitive verb that completes the blank in, *"this change modifies Tailscale to ___________"*. e.g. say *“fix the foobar feature”*, not *“fixing”*, *“fixed”*, or *“fixes”*. Or, as Linux guidelines say:
    > Describe your changes in imperative mood, e.g. “make xyzzy do frotz” instead of “[This patch] makes xyzzy do frotz” or “[I] changed xyzzy to do frotz”, as if you are giving orders to the codebase to change its behaviour."
- the verb after the colon is lowercase
- there is no trailing period
- it should be kept as short as possible (many git viewing tools prefer under ~76 characters, though we aren’t super strict about this)

  Examples:

  | Good Example | notes |
  | ------- | --- |
  | `foo/bar: fix memory leak` |  |
  | `foo/bar: bump deps` |  |
  | `foo/bar: temporarily restrict access` | adverbs are okay |
  | `foo/bar: implement new UI design` | |
  | `control/{foo,bar}: optimize bar` | feel free to use {foo,bar} for common subpackages|

  | Bad Example | notes |
  | ------- | --- |
  | `fixed memory leak` | BAD: missing package prefix |
  | `foo/bar: fixed memory leak` | BAD: past tense |
  | `foo/bar: fixing memory leak` | BAD: present continuous tense; no `-ing` verbs |
  | `foo/bar: bumping deps` | BAD: present continuous tense; no `-ing` verbs | 
  | `foo/bar: new UI design` | BAD: that's a noun phrase; no verb | 
  | `foo/bar: made things larger` | BAD: that's past tense | 
  | `foo/bar: faster algorithm` | BAD: that's an adjective and a noun, not a verb |
  | `foo/bar: Fix memory leak` | BAD: capitalized verb |
  | `foo/bar: fix memory leak.` | BAD: trailing period |
  | `foo/bar:fix memory leak` | BAD: no space after colon |
  | `foo/bar : fix memory leak` | BAD: space before colon |
  | `foo/bar: fix memory leak Fixes #123` | BAD: the "Fixes" shouldn't be part of the title |
  | `!fixup reviewer feedback` | BAD: we don't check in fixup commits; the history should always bissect to a clean, working tree |


For the body (the rest of the description):

- blank line after the subject (first) line
- the text should be wrapped to ~76 characters (to appease git viewing tools, mainly), unless you really need longer lines (e.g. for ASCII art, tables, or long links)
- there must be a `Fixes` or `Updates` line for all non-trivial commits linking to a tracking bug. This goes after the body with a blank newline separating the two. Trivial code clean-up commits can use `Updates #cleanup` instead of an issue.
- `Change-Id` lines should ideally be included in commits in the `corp` repo and are more optional in `tailscale/tailscale`. You can configure Git to do this for you by running `./tool/go run misc/install-git-hooks.go` from the root of the corp repo. This was originally a Gerrit thing and we don't use Gerrit, but it lets us tooling track commits as they're cherry-picked between branches. Also, tools like [git-cleanup](https://github.com/bradfitz/gitutil) use it to clean up your old local branches once they're merged upstream.
- we don't use Markdown in commit messages. (Accidental Markdown like bulleted lists or even headings is fine, but not links)
- we require `Signed-off-by` lines in public repos (such as `tailscale/tailscale`). Add them using `git commit --signoff` or `git commit -s` for short. You can use them in private repos but do not have to.
- when moving code between repos, include the repository name, and git hash that it was moved from/to, so it is easier to trace history/blame.

Please don't use [alternate GitHub-supported
aliases](https://docs.github.com/en/issues/tracking-your-work-with-issues/linking-a-pull-request-to-an-issue)
like `Close` or `Resolves`. Tailscale only uses the verbs `Fixes` and `Updates`.

To link a commit to an issue without marking it fixed—for example, if the commit
is working toward a fix but not yet a complete fix—GitHub requires only that the
issue is mentioned by number in the commit message. By convention, our commits
mention this at the bottom of the message using `Updates`, where `Fixes` might
be expected, even if the number is also mentioned in the body of the commit
message.

For example:

```
some/dir: refactor func Foo

This will make the handling of <corner case>
shorter and easier to test.

Updates #nnnn
```

Please say `Updates` and not other common Github-recognized conventions (that is, don't use `For #nnnn`)

## Public release notes

For changes in `tailscale/tailscale` that fix a significant bug or add a new feature that should be included in the release notes for the next release,
add `RELNOTE: <summary of change>` toward the end of the commit message.
This will aid the release engineer in writing the release notes for the next release.

# Reverts

When you use `git revert` to revert a commit, the default commit message will identify the commit SHA and message that was reverted.  You must expand this message to explain **why** it is being reverted, including a link to the associated issue.

Don't revert reverts. That gets ugly. Send the change anew but reference
the original & earlier revert.

# Other repos

To reference an issue in one repo from a commit in another (for example, fixing an issue in corp with a commit in `tailscale/tailscale`), you need to fully-qualify the issue number with the GitHub org/repo syntax:

```
cipher/rot13: add new super secure cipher

Fixes tailscale/corp#1234
```

Referencing a full URL to the issue is also acceptable, but try to prefer the shorter way.

It's okay to reference the `corp` repo in open source repo commit messages.

# GitHub Pull Requests

In the future we plan to make a bot rewrite all PR bodies programmatically from
the commit messages. But for now (2023-07-25)....

By convention, GitHub Pull Requests follow similar rules to commits, especially
the title of the PR (which should be the first line of the commit). It is less
important to follow these conventions in the PR itself, as it’s the commits that
become a permanent part of the commit history.

It's okay (but rare) for a PR to contain multiple commits. When a PR does
contain multiple commits, call that out in the PR body for reviewers so they can
review each separately.

You don't need to include the `Change-Id` in the description of your PR.
