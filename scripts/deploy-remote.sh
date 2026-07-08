#!/usr/bin/env bash
set -euo pipefail

remote="${MAILHUB_DEPLOY_REMOTE:-}"
remote_dir="${MAILHUB_DEPLOY_DIR:-}"
branch="${MAILHUB_DEPLOY_BRANCH:-$(git branch --show-current)}"
git_url="${MAILHUB_DEPLOY_GIT_URL:-$(git remote get-url origin)}"
stash_remote="${MAILHUB_DEPLOY_STASH_REMOTE:-0}"

if [[ -z "${remote}" || -z "${remote_dir}" ]]; then
  echo "Set MAILHUB_DEPLOY_REMOTE and MAILHUB_DEPLOY_DIR before deploying." >&2
  echo "Example: MAILHUB_DEPLOY_REMOTE=deploy@example.com MAILHUB_DEPLOY_DIR=/opt/mailhub npm run deploy:remote" >&2
  exit 1
fi

if [[ -z "${branch}" ]]; then
  echo "Unable to detect current git branch." >&2
  exit 1
fi

git fetch origin "${branch}"

local_head="$(git rev-parse HEAD)"
remote_head="$(git rev-parse "origin/${branch}")"
if [[ "${local_head}" != "${remote_head}" ]]; then
  echo "Local HEAD is not pushed to origin/${branch}." >&2
  echo "Commit and push first, then run this deploy script." >&2
  exit 1
fi

ssh -o ServerAliveInterval=15 -o ServerAliveCountMax=4 "${remote}" \
  'bash -s' -- "${remote_dir}" "${branch}" "${git_url}" "${stash_remote}" <<'REMOTE'
set -euo pipefail

remote_dir="$1"
branch="$2"
git_url="$3"
stash_remote="$4"

cd "${remote_dir}"

if ! git remote get-url origin >/dev/null 2>&1; then
  git remote add origin "${git_url}"
fi

if [[ -n "$(git status --porcelain)" ]]; then
  if [[ "${stash_remote}" == "1" ]]; then
    git stash push -u -m "pre-deploy-$(date -u +%Y%m%d-%H%M%S)"
  else
    echo "Remote working tree is dirty. Set MAILHUB_DEPLOY_STASH_REMOTE=1 to stash it before pulling." >&2
    git status --short >&2
    exit 1
  fi
fi

git fetch origin "${branch}"
git checkout "${branch}"
git pull --ff-only origin "${branch}"
docker compose up -d --build
docker compose ps
REMOTE
