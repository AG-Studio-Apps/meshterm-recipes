#!/usr/bin/env bash
# One-shot setup of the recipes repository's signing environment (James runs this; agents never do). It reuses the
# template catalogue's PRIMARY key (the app pins the same keys for both, under different trusted-comment kinds):
#
#   1. creates the `recipes-signing` environment on AG-Studio-Apps/meshterm-recipes, limited to `main`
#   2. checks the recovery copy's public key is the pinned primary (862A29760F5FC812)
#   3. sets MINISIGN_KEY (the secret key file) and MINISIGN_PASSWORD (decrypted from primary.passphrase.age with the
#      master passphrase from your password manager) on that environment, both fed on stdin
#
#   bash scripts/setup-recipes-signing.sh /media/$USER/USB1/catalog-primary
#
# Then, in Settings > Environments > recipes-signing: add the required reviewer (the signer account), turn on
# "Prevent self-review", and turn OFF "Allow administrators to bypass". The publish workflow refuses to sign until
# all three hold. Settings > Pages: Source = GitHub Actions.
set -euo pipefail

REPO="AG-Studio-Apps/meshterm-recipes"
ENVIRONMENT="recipes-signing"
PRIMARY_KEY_ID="862A29760F5FC812"
DIR="${1:-}"

die() { printf '\n%s\n' "$*" >&2; exit 1; }
[ -n "$DIR" ] || die "usage: $0 <the catalogue primary recovery folder: primary.key, primary.pub, primary.passphrase.age>"
for f in primary.key primary.pub primary.passphrase.age; do [ -f "$DIR/$f" ] || die "missing $DIR/$f"; done
for t in gh age python3; do command -v "$t" >/dev/null || die "$t is not installed"; done
gh api "repos/$REPO" >/dev/null 2>&1 || die "this gh login cannot see $REPO (create the repository first)"

got=$(python3 -c 'import base64, sys; b = base64.b64decode(open(sys.argv[1]).read().splitlines()[1]); print(b[2:10][::-1].hex().upper())' "$DIR/primary.pub")
[ "$got" = "$PRIMARY_KEY_ID" ] || die "$DIR/primary.pub is key $got, not the pinned primary $PRIMARY_KEY_ID"

if ! gh api "repos/$REPO/environments/$ENVIRONMENT" >/dev/null 2>&1; then
  gh api -X PUT "repos/$REPO/environments/$ENVIRONMENT" >/dev/null
  echo "Created $ENVIRONMENT."
fi
gh api -X PUT "repos/$REPO/environments/$ENVIRONMENT" \
  -F 'deployment_branch_policy[protected_branches]=false' \
  -F 'deployment_branch_policy[custom_branch_policies]=true' >/dev/null
gh api -X POST "repos/$REPO/environments/$ENVIRONMENT/deployment-branch-policies" -f name=main >/dev/null 2>&1 || true
echo "Limited to main."

gh secret set MINISIGN_KEY --env "$ENVIRONMENT" -R "$REPO" < "$DIR/primary.key"
echo "age asks for the MASTER passphrase (password manager):"
age -d "$DIR/primary.passphrase.age" | gh secret set MINISIGN_PASSWORD --env "$ENVIRONMENT" -R "$REPO"
echo "Set MINISIGN_KEY and MINISIGN_PASSWORD on $ENVIRONMENT."
echo
echo "Now: add the required reviewer, Prevent self-review on, administrators may NOT bypass (Settings > Environments),"
echo "and Settings > Pages > Source: GitHub Actions. Then push main and approve the signing job for serial 1."
