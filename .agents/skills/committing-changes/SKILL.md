---
name: committing-changes
description: "Automates the full commit-to-merge workflow: creates a branch, commits, pushes, opens a PR, waits for CI, squash merges, and deletes the branch. Triggers on: commit, ship it, land changes."
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

### 3. Create Branch and Commit

```bash
git checkout -b <branch-name>
git add -A
git commit -m "<commit-message>"
git push -u origin <branch-name>
```

### 4. Create Pull Request

```bash
gh pr create --title "<commit-message>" --body "<pr-description>" --base main
```

- The PR body should summarize the changes concisely

### 5. Wait for CI

Run `scripts/wait-for-ci.sh` to poll the CI status of the PR. The script waits up to 10 minutes, checking every 30 seconds.

- If CI passes, proceed to merge
- If CI fails, stop and report the failure to the user. Do NOT merge.

### 6. Squash Merge

```bash
gh pr merge --squash --delete-branch
```

### 7. Clean Up

```bash
git checkout main
git pull origin main
```

Report success to the user with the merged PR URL.
