#!/usr/bin/env bash
# Signs recipes.json with the OFFLINE emergency key (the template catalogue's emergency key, 61B6FABFCE0C67A9),
# for when the primary key in CI is leaked or lost. The publish workflow sees the committed recipes.json.minisig,
# checks it against keys/recipes-emergency.pub and publishes it as is (the signing job still needs its approval,
# but uses no secret). Adapted from meshdeck-docs scripts/sign-emergency.sh.
#
#   scripts/sign-emergency.sh --key /media/usb1/catalog-emergency/emergency.key
#   scripts/sign-emergency.sh --key FILE --dry-run      # restore test: signs a probe only
#
# Run it on a trusted machine (not the agent box), from a clone of this repository with the new recipes already in
# recipes.json. It refuses unless:
#   - scripts/validate.py passes (against the live file: serial up, nothing dropped),
#   - recipes.json's serial is ABOVE the live one (fetched with a cache-busting query),
#   - the signature verifies against keys/recipes-emergency.pub with the trusted comment
#     `recipes=host-recipes version=<serial> date=<date>`.
# Only then is recipes.json.minisig written. minisign asks for the key's passphrase (from the password manager).
# Then commit recipes.json and recipes.json.minisig together and push to main. After the incident, the next change
# must delete recipes.json.minisig (the publish workflow refuses a committed signature that no longer matches).
#
# Incident hygiene: run it only from a clone whose scripts/ and keys/ match a commit you have reviewed: it refuses
# uncommitted changes there and prints both tree ids.
#
# For tests only: --pub FILE verifies against another public key, --live-file FILE stands in for the live
# recipes.json, and --no-gates skips the validator.
set -euo pipefail
umask 077

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
LIVE_URL="https://ag-studio-apps.github.io/meshterm-recipes/recipes.json"
KEY=""
PUB="$REPO_DIR/keys/recipes-emergency.pub"
DRY_RUN=0
LIVE_FILE=""
GATES=1

usage() { sed -n '7,8p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --key) shift; KEY="${1:-}" ;;
    --dry-run) DRY_RUN=1 ;;
    --pub) shift; PUB="${1:-}" ;;
    --live-file) shift; LIVE_FILE="${1:-}" ;;
    --no-gates) GATES=0 ;;
    -h|--help) usage ;;
    *) echo "unknown argument $1" >&2; usage ;;
  esac
  shift
done

for tool in minisign python3; do
  command -v "$tool" >/dev/null || { echo "$tool is not installed" >&2; exit 1; }
done
[ -n "$KEY" ] || { echo "--key FILE is required (the emergency secret key, from the offline copy)" >&2; usage; }
[ -f "$KEY" ] || { echo "no key file at $KEY" >&2; exit 2; }
[ -f "$PUB" ] || { echo "no public key at $PUB" >&2; exit 1; }
if head -n 1 "$KEY" | grep -qi 'public key'; then
  echo "$KEY is a public key; --key takes the SECRET key file" >&2; exit 2
fi
case "$(cd "$(dirname "$KEY")" && pwd)/" in
  "$HOME/appfactory/"*) echo "warning: the emergency key should not live under ~/appfactory (agents on the build box can read it)" >&2 ;;
esac

key_id() { python3 -c 'import base64, sys; b = base64.b64decode(open(sys.argv[1]).read().splitlines()[1]); print(b[2:10][::-1].hex().upper())' "$1"; }
PUB_ID="$(key_id "$PUB")"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# --- Restore test ------------------------------------------------------------------------
if [ "$DRY_RUN" -eq 1 ]; then
  printf '{"probe": "emergency restore test", "at": "%s"}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$TMP/probe.json"
  echo "Signing a probe with $KEY (minisign asks for its passphrase)."
  minisign -S -s "$KEY" -m "$TMP/probe.json" -x "$TMP/probe.json.minisig" -t "recipes restore test" >/dev/null
  if minisign -V -q -p "$PUB" -m "$TMP/probe.json" -x "$TMP/probe.json.minisig"; then
    echo "OK: the emergency key signs, and its signature verifies against $(basename "$PUB") (key id $PUB_ID)."
    echo "Nothing was written to the repository."
    exit 0
  fi
  echo "FAILED: this key does not match $(basename "$PUB") (key id $PUB_ID)." >&2
  exit 1
fi

# --- Emergency signature -----------------------------------------------------------------
if git -C "$REPO_DIR" rev-parse --git-dir >/dev/null 2>&1; then
  if [ -n "$(git -C "$REPO_DIR" status --porcelain -- scripts keys)" ]; then
    echo "refusing: scripts/ or keys/ have uncommitted changes; sign only from reviewed code" >&2
    git -C "$REPO_DIR" status --short -- scripts keys >&2
    exit 1
  fi
  echo "Code in use: commit $(git -C "$REPO_DIR" rev-parse --short=12 HEAD), scripts/ tree $(git -C "$REPO_DIR" rev-parse --short=12 HEAD:scripts), keys/ tree $(git -C "$REPO_DIR" rev-parse --short=12 HEAD:keys)."
  echo "Compare them with the ids recorded for the reviewed pipeline before typing the passphrase."
else
  echo "warning: $REPO_DIR is not a git clone; the code in use cannot be checked" >&2
fi
CATALOG="$REPO_DIR/recipes.json"
SIG="$REPO_DIR/recipes.json.minisig"
[ -f "$CATALOG" ] || { echo "no recipes.json in $REPO_DIR" >&2; exit 1; }
[ -e "$SIG" ] && { echo "$SIG already exists; delete it first if you mean to re-sign" >&2; exit 1; }

version="$(python3 -c 'import json, sys; v = json.load(open(sys.argv[1]))["serial"]; assert type(v) is int and v > 0; print(v)' "$CATALOG")" \
  || { echo "recipes.json has no positive integer serial" >&2; exit 1; }
date_field="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["date"])' "$CATALOG")"

if [ -n "$LIVE_FILE" ]; then
  cp "$LIVE_FILE" "$TMP/live.json"
else
  command -v curl >/dev/null || { echo "curl is not installed" >&2; exit 1; }
  curl -fsS --max-time 20 -H 'Cache-Control: no-cache' "$LIVE_URL?r=$(date +%s)$RANDOM" -o "$TMP/live.json" \
    || { echo "cannot fetch the live recipes from $LIVE_URL; refusing (the serial must be checked)" >&2; exit 1; }
fi
live="$(python3 -c 'import json, sys; v = json.load(open(sys.argv[1]))["serial"]; assert type(v) is int; print(v)' "$TMP/live.json")" \
  || { echo "the live recipes file has no integer serial; refusing" >&2; exit 1; }
if [ "$version" -le "$live" ]; then
  echo "refusing: recipes.json is serial $version, the live file is serial $live." >&2
  echo "An emergency signature must publish a NEWER serial (the app refuses a rollback, and the same" >&2
  echo "serial with different bytes). Set \"serial\" to $((live + 1)) and run again." >&2
  exit 1
fi


if [ "$GATES" -eq 1 ]; then
  echo "Running the validator against the live file."
  python3 "$REPO_DIR/scripts/validate.py" --previous-file "$TMP/live.json" \
    || { echo "refusing: the validator fails; an emergency signature must not cover that" >&2; exit 1; }
fi

comment="recipes=host-recipes version=$version date=$date_field"
echo "Signing recipes.json serial $version with the emergency key (minisign asks for its passphrase)."
minisign -S -s "$KEY" -m "$CATALOG" -x "$TMP/recipes.json.minisig" -t "$comment" >/dev/null

minisign -V -q -p "$PUB" -m "$CATALOG" -x "$TMP/recipes.json.minisig" \
  || { echo "FAILED: the signature does not verify against $(basename "$PUB") (key id $PUB_ID). Wrong key?" >&2; exit 1; }
got="$(sed -n 3p "$TMP/recipes.json.minisig")"
[ "$got" = "trusted comment: $comment" ] || { echo "FAILED: trusted comment is '$got'" >&2; exit 1; }

mv "$TMP/recipes.json.minisig" "$SIG"
chmod 644 "$SIG"
echo
echo "Wrote recipes.json.minisig: serial $version, emergency key $PUB_ID, verified."
echo "Next:"
echo "  git add recipes.json recipes.json.minisig"
echo "  git commit -m \"Recipes serial $version (emergency signature)\""
echo "  git push origin main      # then approve the recipes-signing job"
echo "After the incident, delete recipes.json.minisig in the next change."
