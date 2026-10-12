#!/usr/bin/env python3
"""Validate recipes.json exactly as meshTerm does before it uses one, plus the publishing rules.

    scripts/validate.py                          # recipes.json in the repository root
    scripts/validate.py --previous-ref origin/main
                                                 # also: the serial went up if anything changed, the date did not go
                                                 # back, and nothing the previous file had was dropped
    scripts/validate.py --self-test              # the rules against known good and bad files

The app-side rules (MeshTermFailures HostRecipeDocument / HostRecipeTemplate) live in recipes_lib.py; this script adds
the repository's own: every `ci` block is well formed, and every intent the bundled apps ask for is present.
"""
import argparse
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import recipes_lib as lib  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CI_KEYS = {"check", "skip", "needs", "before", "packages", "xfail", "skipOn", "rootOnly", "userOnly"}


def check_ci(doc):
    """The CI block (read only by scripts/run-recipes.py; the apps ignore it)."""
    for intent, variants in doc["intents"].items():
        for index, variant in enumerate(variants):
            where = f"{intent}[{index}].ci"
            ci = variant.get("ci")
            if ci is None:
                raise lib.RecipeError(f"{where}: every variant needs a ci block (a check, or a skip with its reason)")
            unknown = set(ci) - CI_KEYS
            if unknown:
                raise lib.RecipeError(f"{where}: unknown key {sorted(unknown)[0]}")
            if ("check" in ci) == ("skip" in ci):
                raise lib.RecipeError(f"{where}: exactly one of check (a shell assertion) or skip (the reason)")
            for key in ("check", "skip", "before", "rootOnly", "userOnly"):
                if key in ci and (not isinstance(ci[key], str) or not ci[key].strip()):
                    raise lib.RecipeError(f"{where}.{key} must be a non-empty string")
            if "rootOnly" in ci and "userOnly" in ci:
                raise lib.RecipeError(f"{where}: rootOnly and userOnly together")
            if "needs" in ci and (not isinstance(ci["needs"], list)
                                  or not all(n in doc["packages"] for n in ci["needs"])):
                raise lib.RecipeError(f"{where}.needs: package ids from the packages table")
            if "packages" in ci and (not isinstance(ci["packages"], list) or not ci["packages"]
                                     or not all(isinstance(p, str) and lib.PACKAGE.match(p) for p in ci["packages"])):
                raise lib.RecipeError(f"{where}.packages: package names")
            for key in ("xfail", "skipOn"):
                if key in ci and (not isinstance(ci[key], dict)
                                  or not all(isinstance(v, str) and v.strip() for v in ci[key].values())):
                    raise lib.RecipeError(f"{where}.{key}: image -> reason")
            if "{{packages}}" in variant["run"] and "packages" not in ci and intent != "packages.install":
                if "check" in ci:
                    raise lib.RecipeError(f"{where}: a {{{{packages}}}} recipe needs ci.packages to test with")


def git_show(ref, path):
    try:
        return subprocess.run(["git", "-C", ROOT, "show", f"{ref}:{path}"], check=True, capture_output=True).stdout
    except subprocess.CalledProcessError:
        return None


def validate(data, previous=None, need_ci=True):
    doc = lib.load(data)
    if need_ci:
        check_ci(doc)
    if previous is not None:
        old = lib.load(previous)
        if data != previous:
            if doc["serial"] <= old["serial"]:
                raise lib.RecipeError(f"recipes.json changed but serial {doc['serial']} is not above the previous "
                                      f"{old['serial']} (a changed file always takes a new serial)")
            if doc["date"] < old["date"]:
                raise lib.RecipeError(f"date {doc['date']} is before the previous {old['date']}")
        lib.check_covers(doc, old)
    return doc


def self_test():
    with open(os.path.join(ROOT, "recipes.json"), "rb") as handle:
        good = handle.read()
    base = json.loads(good)

    def variant_of(run, **extra):
        doc = json.loads(good)
        doc["intents"]["x.y"] = [dict({"families": ["apt"], "run": run, "ci": {"skip": "test"}}, **extra)]
        return json.dumps(doc).encode()

    bad = {
        "unknown placeholder": variant_of("{{root}}apt-get install -y x"),
        "literal sudo": variant_of("sudo apt-get install -y x"),
        "literal su": variant_of("su -c 'apk add x'"),
        "sudo mid-command": variant_of("echo {{sudo}}apt-get install -y x"),
        "newline": variant_of("a\nb"),
        "non-ASCII": variant_of("apt-get install -y tа"),
        "admin not bool": variant_of("a", admin=1),
        "empty versions": variant_of("a", versions={}),
        "inverted versions": variant_of("a", versions={"min": "24.04", "below": "22.04"}),
        "bad package name": json.dumps(dict(base, packages=dict(base["packages"], curl={"apt": "Curl"}))).encode(),
        "wrong kind": json.dumps(dict(base, kind="templates")).encode(),
        "schema 2": json.dumps(dict(base, schema=2)).encode(),
        "bool serial": json.dumps(dict(base, serial=True)).encode(),
        "bad date": json.dumps(dict(base, date="2026-13-01")).encode(),
        "duplicate key": good.replace(b'"kind": "host-recipes",', b'"kind": "host-recipes", "kind": "host-recipes",', 1),
    }
    failures = 0
    for name, data in bad.items():
        try:
            validate(data, need_ci=False)
            print(f"self-test FAIL: '{name}' was accepted")
            failures += 1
        except lib.RecipeError:
            pass
    # Coverage and serial rules against the committed file.
    dropped = json.loads(good)
    dropped["serial"] += 1
    dropped["intents"].pop("tmux.install")
    same_serial = json.loads(good)
    same_serial["intents"]["tmux.install"][0]["run"] = "{{sudo}}apt-get install -y tmux"
    for name, data in {"drops an intent": json.dumps(dropped).encode(),
                       "changed without a serial bump": json.dumps(same_serial).encode()}.items():
        try:
            validate(data, previous=good, need_ci=False)
            print(f"self-test FAIL: '{name}' was accepted")
            failures += 1
        except lib.RecipeError:
            pass
    try:
        validate(good, previous=good)
    except lib.RecipeError as error:
        print(f"self-test FAIL: the committed file is refused: {error}")
        failures += 1
    # The resolver: an id variant beats the family; a range needs a VERSION_ID.
    doc = lib.load(good)
    ubuntu = lib.select(doc, "compose.install-package", "apt", "ubuntu")
    debian = lib.select(doc, "compose.install-package", "apt", "debian")
    if ubuntu is None or debian is not None:
        print("self-test FAIL: compose.install-package selection")
        failures += 1
    if lib.render("{{sudo}}usermod -aG docker {{user}}", True, user="-x") is not None:
        print("self-test FAIL: an option-shaped user rendered")
        failures += 1
    print("self-test:", "FAIL" if failures else "OK")
    return 1 if failures else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("file", nargs="?", default=os.path.join(ROOT, "recipes.json"))
    parser.add_argument("--previous-ref", help="a git ref whose recipes.json this one must follow")
    parser.add_argument("--previous-file", help="a file this one must follow")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    with open(args.file, "rb") as handle:
        data = handle.read()
    previous = None
    if args.previous_file:
        with open(args.previous_file, "rb") as handle:
            previous = handle.read()
    elif args.previous_ref:
        previous = git_show(args.previous_ref, "recipes.json")
        if previous is None:
            print(f"note: {args.previous_ref} has no recipes.json (the first publish)")
    try:
        doc = validate(data, previous)
    except lib.RecipeError as error:
        print(f"::error::recipes.json: {error}")
        return 1
    variants = sum(len(v) for v in doc["intents"].values())
    print(f"OK: serial {doc['serial']} ({doc['date']}), {len(doc['intents'])} intents, {variants} variants, "
          f"{len(doc['packages'])} packages")
    return 0


if __name__ == "__main__":
    sys.exit(main())
