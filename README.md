# gh-amp

![GitHub Issues](https://img.shields.io/github/issues/fini-net/gh-amp)
![GitHub Pull Requests](https://img.shields.io/github/issues-pr/fini-net/gh-amp)
![GitHub License](https://img.shields.io/github/license/fini-net/gh-amp)
![GitHub watchers](https://img.shields.io/github/watchers/fini-net/gh-amp)

A GitHub CLI extension that streamlines the PR review workflow. `amp` stands for
**Approve, Merge, Pull** -- the three actions that make up the core PR workflow.

![gh amp banner image](docs/gh-amp-banner.png)

## Installation

```bash
gh extension install fini-net/gh-amp
```

For the best experience with `gh-amp` we recommend you install our
[other github extension "gh-observer"](https://github.com/fini-net/gh-observer),
but it is not required.

```bash
gh extension install fini-net/gh-observer
```

`gh-observer` provides a more informative and attractive summary of the
GitHub Actions that hae run on a pull request.

### Pre-requisites

For using this tool you will need to have `jq` installed.  On MacOS:

```bash
brew install jq
```

For Debian/Ubuntu-based Linux you can install it with:

```bash
sudo apt-get install jq
```

For developing in this repo, the `.just/lib/install-prerequisites.sh`
script will take care of installing everything.

## Demo

Here is an animation showing `gh amp review` on a PR in the
[gh-observer repo](https://github.com/fini-net/gh-observer):

![animation of gh amp review](docs/review-demo.gif)

Note: this demo merges a PR with known CI failures because the
[gh-observer repo](https://github.com/fini-net/gh-observer) uses
[`Super-Linter`](https://github.com/super-linter/super-linter) and
intentionally keeps some linting failures active to exercise CI
status display. `gh amp` correctly reports these failures — the
merge proceeds because the failures are expected in that repo.

## Commands

### `gh amp review`

Interactive workflow: select a PR, view its details, then approve, merge, and
pull it. This is the primary use case for the extension.

```bash
# Interactive review for current repo
gh amp review

# Review PRs in a specific repo
gh amp review -R fini-net/gh-amp

# Review only PRs by a specific author
gh amp review --author @me

# Review with a different merge strategy
gh amp review --merge-strategy rebase
```

The review command shows the PR diff, then presents a menu with options to:

1. View CI status
2. Approve PR
3. Merge PR (configurable strategy: squash, merge, or rebase)
4. Sync base branch (checkout and pull the base branch)
5. Approve + Merge + Sync (full workflow)
6. Open in browser

### `gh amp list`

List pull requests with optional filters.

```bash
# List open PRs for the current repo
gh amp list

# List PRs authored by you
gh amp list --author @me

# List PRs with a specific label
gh amp list --label bug

# List PRs in a different repo
gh amp list -R fini-net/gh-amp

# List merged PRs
gh amp list --state merged
```

### `gh amp status`

Show CI status for a pull request.

```bash
# Show status for current branch's PR
gh amp status

# Show status for a specific PR
gh amp status 42

# Show status for a PR in a different repo
gh amp -R fini-net/gh-amp status 42

# Show status with a different order of arguments
gh amp status 42 -R fini-net/gh-amp
```

## Flags

- **`-R, --repo`** -- Select another repository (`[HOST/]OWNER/REPO`)
- **`-A, --author`** -- Filter by PR author
- **`-l, --label`** -- Filter by label
- **`-s, --state`** -- Filter by state: `open`, `closed`, `merged`, `all` (default: `open`)
- **`-L, --limit`** -- Maximum number of PRs to fetch (default: 30)
- **`-S, --search`** -- Search query for filtering PRs
- **`--merge-strategy`** -- Merge strategy: `squash`, `merge`, `rebase` (default: `squash`)
- **`--version`** -- Show version
- **`-h, --help`** -- Show help

## Contributing

- [Code of Conduct](.github/CODE_OF_CONDUCT.md)
- [Contributing Guide](.github/CONTRIBUTING.md) includes a step-by-step guide to our
  [development process](.github/CONTRIBUTING.md#development-process).

## Support & Security

- [Getting Support](.github/SUPPORT.md)
- [Security Policy](.github/SECURITY.md)
