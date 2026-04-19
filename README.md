# gh-amp

![GitHub Issues](https://img.shields.io/github/issues/fini-net/gh-amp)
![GitHub Pull Requests](https://img.shields.io/github/issues-pr/fini-net/gh-amp)
![GitHub License](https://img.shields.io/github/license/fini-net/gh-amp)
![GitHub watchers](https://img.shields.io/github/watchers/fini-net/gh-amp)

A GitHub CLI extension that streamlines the PR review workflow. `amp` stands for
**Approve, Merge, Pull** -- the three actions that make up the core PR workflow.

## Installation

```bash
gh extension install fini-net/gh-amp
```

## Commands

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
gh amp status 42 -R fini-net/gh-amp
```

### `gh amp review`

Interactive workflow: select a PR, view its details, then approve, merge, and
pull it.

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

The review command presents a menu with options to:

1. View CI status
2. View diff
3. Approve PR
4. Merge PR (configurable strategy: squash, merge, or rebase)
5. Pull branch locally
6. Approve + Merge + Pull (full workflow)
7. Open in browser

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
