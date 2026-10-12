#!/usr/bin/env python3
"""Checks a recipes.json / recipes.json.minisig pair exactly as meshTerm's contract does.

Adapted from meshdeck-docs scripts/catalog_signature.py (the template catalogue), with the SAME keys and a
DISTINCT kind. A pair is good when: the signature names a key in keys/ (by its 8-byte key id), minisign verifies
the body AND the trusted comment against that key, the trusted comment is
`recipes=host-recipes version=<serial> date=<YYYY-MM-DD>` (optionally followed by ` commit=<40 hex>`, which the app
ignores), <serial> equals the body's top-level `serial` and <date> its `date`. A catalogue signature
(`catalog=templates ...`) never passes here, and the app refuses one too.

    recipes_signature.py verify --body F --sig F [--role primary|emergency|any] [--expect-serial N]
    recipes_signature.py reuse  --url URL --body recipes.json --out SIG
    recipes_signature.py smoke  --url URL --expect-body recipes.json [--tries 4] [--interval 200]

`reuse` (publish workflow, no secrets): fetch the live pair with a cache-busting query; when the
live body is byte-identical to --body and its signature passes, write the live signature to --out
(exit 0), else exit 3 with the reason (the run then needs a fresh signature). `smoke` (after a
deploy): the live pair must pass and the live body must equal --expect-body; retried, because the
CDN caches each file for up to 600 s. Needs the `minisign` binary.
"""
import argparse
import base64
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
KEYS_DIR = os.path.join(HERE, "..", "keys")
ROLES = ("primary", "emergency")
COMMENT = re.compile(r"^recipes=host-recipes version=([1-9][0-9]*) date=([0-9]{4}-[0-9]{2}-[0-9]{2})( commit=[0-9a-f]{40})?$")
BODY_CAP = 256 * 1024
SIG_CAP = 4 * 1024
DEFAULT_URL = "https://ag-studio-apps.github.io/meshterm-recipes/recipes.json"


class PairError(Exception):
    pass


def _key_id(blob):
    # minisign prints the little-endian 8-byte key number as hex.
    return blob[2:10][::-1].hex().upper()


def public_key_id(path):
    with open(path, encoding="utf-8") as handle:
        lines = handle.read().splitlines()
    if len(lines) < 2:
        raise PairError(f"{path} is not a minisign public key")
    blob = base64.b64decode(lines[1].strip(), validate=True)
    if len(blob) != 42 or blob[:2] != b"Ed":
        raise PairError(f"{path} is not an Ed25519 minisign public key")
    return _key_id(blob)


def roster(keys_dir=KEYS_DIR):
    """{role: (path, key id)} for keys/recipes-<role>.pub."""
    out = {}
    for role in ROLES:
        path = os.path.join(keys_dir, f"recipes-{role}.pub")
        if os.path.exists(path):
            out[role] = (path, public_key_id(path))
    ids = [kid for _, kid in out.values()]
    if len(set(ids)) != len(ids):
        raise PairError("the primary and emergency keys share a key id (the app\'s verifier would stop at the first)")
    return out


def parse_signature(data):
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise PairError("the signature is not text") from None
    lines = text.splitlines()
    if len(lines) < 4 or not lines[0].startswith("untrusted comment:") \
            or not lines[2].startswith("trusted comment: "):
        raise PairError("the signature is not in minisign's format")
    try:
        blob = base64.b64decode(lines[1].strip(), validate=True)
    except ValueError:
        raise PairError("the signature line is not base64") from None
    if len(blob) != 74 or blob[:2] not in (b"Ed", b"ED"):
        raise PairError("the signature is not an Ed25519 minisign signature")
    return _key_id(blob), lines[2][len("trusted comment: "):]


def body_version(body):
    """(serial, date) of a recipes body."""
    try:
        doc = json.loads(body.decode("utf-8"))
        serial, date = doc.get("serial"), doc.get("date")
    except (ValueError, UnicodeDecodeError, AttributeError):
        raise PairError("the body is not a JSON object") from None
    if not isinstance(serial, int) or isinstance(serial, bool):
        raise PairError("the body has no integer serial")
    if not isinstance(date, str):
        raise PairError("the body has no date")
    return serial, date


def check_pair(body, signature, role="any", expect_version=None, keys_dir=KEYS_DIR):
    """Raise PairError unless the pair passes. Returns (role, version, trusted comment)."""
    keys = roster(keys_dir)
    signer_id, comment = parse_signature(signature)
    matches = [r for r, (_, kid) in keys.items() if kid == signer_id]
    if not matches:
        raise PairError(f"the signature's key id {signer_id} is not in keys/ ({', '.join(f'{r} {k}' for r, (_, k) in keys.items())})")
    signer = matches[0]
    if role != "any" and signer != role:
        raise PairError(f"signed by the {signer} key, expected the {role} key")
    with tempfile.TemporaryDirectory() as tmp:
        body_path, sig_path = os.path.join(tmp, "body"), os.path.join(tmp, "body.minisig")
        with open(body_path, "wb") as handle:
            handle.write(body)
        with open(sig_path, "wb") as handle:
            handle.write(signature)
        result = subprocess.run(["minisign", "-V", "-q", "-p", keys[signer][0], "-m", body_path, "-x", sig_path],
                                capture_output=True, text=True)
        if result.returncode != 0:
            raise PairError(f"minisign: the signature does not verify against keys/recipes-{signer}.pub "
                            f"({(result.stderr or result.stdout).strip()[:200]})")
    match = COMMENT.match(comment)
    if not match:
        raise PairError(f"trusted comment {comment!r} is not "
                        "'recipes=host-recipes version=<serial> date=<YYYY-MM-DD>[ commit=<sha>]'")
    signed, signed_date = int(match.group(1)), match.group(2)
    version, date = body_version(body)
    if signed != version:
        raise PairError(f"the signature is for serial {signed}, the body is serial {version}")
    if signed_date != date:
        raise PairError(f"the signature is dated {signed_date}, the body {date}")
    if expect_version is not None and version != expect_version:
        raise PairError(f"serial {version}, expected {expect_version}")
    return signer, version, comment


def fetch(url, cap, token):
    request = urllib.request.Request(f"{url}?r={token}", headers={
        "Cache-Control": "no-cache", "User-Agent": "recipes-publish-check"})
    with urllib.request.urlopen(request, timeout=20) as response:
        data = response.read(cap + 1)
    if len(data) > cap:
        raise PairError(f"{url} is larger than {cap} bytes")
    return data


def fetch_live(url):
    """(body, signature or None). One random query shared by both, as the app's retry does."""
    token = secrets.token_hex(8)
    body = fetch(url, BODY_CAP, token)
    try:
        signature = fetch(url + ".minisig", SIG_CAP, token)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return body, None
        raise
    return body, signature


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    verify = sub.add_parser("verify")
    verify.add_argument("--body", required=True)
    verify.add_argument("--sig", required=True)
    verify.add_argument("--role", choices=("any",) + ROLES, default="any")
    verify.add_argument("--expect-serial", dest="expect_version", type=int)
    reuse = sub.add_parser("reuse")
    reuse.add_argument("--url", default=DEFAULT_URL)
    reuse.add_argument("--body", required=True)
    reuse.add_argument("--out", required=True)
    smoke = sub.add_parser("smoke")
    smoke.add_argument("--url", default=DEFAULT_URL)
    smoke.add_argument("--expect-body", required=True)
    smoke.add_argument("--tries", type=int, default=4)
    smoke.add_argument("--interval", type=int, default=200)
    for p in (verify, reuse, smoke):
        p.add_argument("--keys-dir", default=KEYS_DIR)
    args = parser.parse_args(argv)

    if args.command == "verify":
        try:
            with open(args.body, "rb") as handle:
                body = handle.read()
            with open(args.sig, "rb") as handle:
                signature = handle.read()
            signer, version, comment = check_pair(body, signature, args.role, args.expect_version, args.keys_dir)
        except (PairError, OSError) as error:
            print(f"FAIL: {error}", file=sys.stderr)
            return 1
        print(f"OK: version {version}, signed by the {signer} key ({comment})")
        return 0

    if args.command == "reuse":
        with open(args.body, "rb") as handle:
            body = handle.read()
        try:
            live, signature = fetch_live(args.url)
            if live != body:
                raise PairError(f"the live recipes.json is serial {body_version(live)[0]} with different bytes")
            if signature is None:
                raise PairError("the live site has no recipes.json.minisig")
            signer, version, comment = check_pair(live, signature, keys_dir=args.keys_dir)
        except (PairError, OSError, urllib.error.URLError) as error:
            print(f"cannot reuse the live signature: {error}")
            return 3
        with open(args.out, "wb") as handle:
            handle.write(signature)
        print(f"reusing the live signature: version {version}, {signer} key ({comment})")
        return 0

    with open(args.expect_body, "rb") as handle:
        expected = handle.read()
    expected_version = body_version(expected)[0]
    last, lagging = "", False
    for attempt in range(1, args.tries + 1):
        try:
            live, signature = fetch_live(args.url)
            if signature is None:
                raise PairError("recipes.json.minisig is missing")
            signer, version, comment = check_pair(live, signature, keys_dir=args.keys_dir)
            if live == expected:
                print(f"OK: the live pair is version {version}, signed by the {signer} key ({comment})")
                return 0
            if version > expected_version:
                print(f"::error::ALARM: the live recipes file is serial {version}, above the published "
                      f"{expected_version}. The hosting serves something this repository did not publish.")
                return 1
            lagging, last = True, f"the live pair verifies but is version {version} (expected {expected_version})"
        except (PairError, OSError, urllib.error.URLError) as error:
            lagging, last = False, str(error)
        print(f"attempt {attempt}/{args.tries}: {last}")
        if attempt < args.tries:
            time.sleep(args.interval)
    if lagging:
        print(f"::warning::{last} after {args.tries} tries; most likely the CDN has not caught up. "
              f"Check {args.url} again in a few minutes.")
        return 0
    print(f"::error::the live recipes pair does not verify: {last}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
