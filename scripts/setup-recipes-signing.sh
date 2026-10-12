#!/usr/bin/env bash
# FRESH REPOSITORY ONLY. AG-Studio-Apps/meshterm-recipes is already set up (2026-10-11): Pages from GitHub Actions,
# the `recipes-signing` environment (required reviewer, main only) and its MINISIGN_KEY / MINISIGN_PASSWORD secrets.
# Keep this for re-creating the environment on a new repository (a fork, a rename, a disaster): it creates
# `recipes-signing` limited to `main` and prints what is left to do by hand. It never touches a secret.
#
#   REPO=AG-Studio-Apps/meshterm-recipes bash scripts/setup-recipes-signing.sh
#
# By hand afterwards (Settings > Environments > recipes-signing): add the required reviewer and make sure
# "Allow administrators to bypass" is OFF (the sign job refuses otherwise; self-review is allowed). Add the secrets
# MINISIGN_KEY (the template catalogue's PRIMARY minisign secret key file, from its recovery copy) and
# MINISIGN_PASSWORD (its passphrase), e.g. `gh secret set MINISIGN_KEY --env recipes-signing -R "$REPO" < primary.key`.
# Settings > Pages: Source = GitHub Actions.
set -euo pipefail

REPO="${REPO:-AG-Studio-Apps/meshterm-recipes}"
ENVIRONMENT="recipes-signing"

die() { printf '\n%s\n' "$*" >&2; exit 1; }
command -v gh >/dev/null || die "gh is not installed"
gh api "repos/$REPO" >/dev/null 2>&1 || die "this gh login cannot see $REPO"

if gh api "repos/$REPO/environments/$ENVIRONMENT" >/dev/null 2>&1; then
  echo "$ENVIRONMENT already exists on $REPO: leaving its reviewers and secrets alone."
else
  gh api -X PUT "repos/$REPO/environments/$ENVIRONMENT" >/dev/null
  echo "Created $ENVIRONMENT."
fi
gh api -X PUT "repos/$REPO/environments/$ENVIRONMENT" \
  -F 'deployment_branch_policy[protected_branches]=false' \
  -F 'deployment_branch_policy[custom_branch_policies]=true' >/dev/null
gh api -X POST "repos/$REPO/environments/$ENVIRONMENT/deployment-branch-policies" -f name=main >/dev/null 2>&1 || true
echo "Limited to main."
secrets="$(gh api "repos/$REPO/environments/$ENVIRONMENT/secrets" --jq '[.secrets[].name]|join(",")' 2>/dev/null || true)"
echo "Secrets on $ENVIRONMENT: ${secrets:-none} (expected MINISIGN_KEY,MINISIGN_PASSWORD; set them by hand)."
echo "Now: the required reviewer, admin bypass OFF, and Pages > Source: GitHub Actions."
