---
name: committing-changes
description: "Automates the full commit-to-merge workflow: creates a branch, commits, pushes, opens a PR, waits for CI, squash merges, and deletes the branch. Also handles creating new releases. Triggers on: commit, ship it, land changes, release, new release, cut a release."
---

# Committing Changes

Automates the full git workflow from commit to merge in a single action.

## Prerequisites

- `gh` CLI must be installed and authenticated
- Working directory must be a git repository with a GitHub remote
- There must be uncommitted or staged changes to commit

## Workflow

Follow these steps in order. Stop and report errors at any step.

### 1. Pre-flight Checks

- Run `make test` (or `go test ./...`) to ensure all tests pass before proceeding
- Confirm there are changes to commit (`git status`)
- If no changes exist, stop and inform the user

### 2. Determine Branch Name and Commit Message

- Analyze the staged/unstaged changes to understand what was done
- Generate a branch name following the convention: `feat/short-description` or `fix/short-description`
- Generate a commit message following Conventional Commits: `feat: ...`, `fix: ...`, `refactor: ...`, `docs: ...`, `test: ...`
- Present the branch name and commit message to the user and ask for confirmation before proceeding

### 3. Update Documentation

- Review the changes being committed and determine if they affect user-facing behavior (new flags, changed output, new subcommands, etc.)
- If so, update `README.md` (and any other relevant docs) to reflect the changes
- If the changes are purely internal (refactors, test additions, CI changes), skip this step

### 4. Create Branch and Commit

```bash
git checkout -b <branch-name>
git add -A
git commit -m "<commit-message>"
git push -u origin <branch-name>
```

### 5. Create Pull Request

```bash
gh pr create --title "<commit-message>" --body "<pr-description>" --base main
```

- The PR body should summarize the changes concisely

### 6. Wait for CI

Before waiting, check the CI workflow path filters in `.github/workflows/ci.yaml`. If none of the changed files match the paths listed in the `on.pull_request.paths` filter, skip waiting and proceed directly to merge.

Otherwise, run `scripts/wait-for-ci.sh` to poll the CI status of the PR. The script waits up to 10 minutes, checking every 30 seconds.

- If CI passes, proceed to merge
- If CI fails, stop and report the failure to the user. Do NOT merge.

### 7. Squash Merge

```bash
gh pr merge --squash --delete-branch
```

### 8. Clean Up

```bash
git checkout main
git pull origin main
```

Report success to the user with the merged PR URL.

## Creating a Release

When the user asks to create a new release (e.g., "new release", "cut a release"):

- Update the `VERSION` file with the new version number
- Update all version references in the "Pre-built binaries" section of `README.md`: the archive filenames and download URLs in the platform table, and the `curl` install example
- Then follow the normal commit workflow above with message `chore: bump version to <version>`
