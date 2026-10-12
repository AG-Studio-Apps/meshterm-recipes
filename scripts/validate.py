#!/usr/bin/env python3
"""Validate recipes.json exactly as meshTerm does before it uses one, plus the publishing rules.

    scripts/validate.py                          # recipes.json in the repository root
    scripts/validate.py --previous-ref origin/main
                                                 # also: the serial went up if anything changed, the date did not go
                                                 # back, and nothing the previous file had was dropped
    scripts/validate.py --self-test              # the rules against known good and bad files (ci/format-cases.json,
                                                 # the table meshTerm's Swift tests run too)
    scripts/validate.py --declared ci/serial3-declared.json --baseline ci/serial3-baseline.json --previous-ref main
                                                 # every data change against the previous file (plus the baseline's
                                                 # new intents and package ids, the app's code text) is declared,
                                                 # and every declared change is there

The app-side rules (MeshTermFailures HostRecipeDocument / HostRecipeTemplate) live in recipes_lib.py; this script adds
the repository's own: every `ci` block is well formed, and every intent the bundled apps ask for is present.
"""
import argparse
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import recipes_lib as lib  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CI_KEYS = {"check", "skip", "needs", "before", "packages", "xfail", "skipOn", "rootOnly", "userOnly", "port", "proto",
           "group", "path", "user", "su"}
FORMAT_CASES = os.path.join(ROOT, "ci", "format-cases.json")


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
            if "port" in ci and (not lib.is_int(ci["port"]) or not 1 <= ci["port"] <= 65535):
                raise lib.RecipeError(f"{where}.port: 1-65535")
            if "proto" in ci and ci["proto"] not in lib.PROTOS:
                raise lib.RecipeError(f"{where}.proto: tcp or udp")
            if "group" in ci and ci["group"] not in lib.GROUPS:
                raise lib.RecipeError(f"{where}.group: sudo or wheel")
            if "user" in ci and (not isinstance(ci["user"], str) or lib.user_word(ci["user"]) != ci["user"]):
                raise lib.RecipeError(f"{where}.user: a plain user name")
            if "su" in ci and ci["su"] is not True:
                raise lib.RecipeError(f"{where}.su: true (also run the su -c form on the suMode images)")
            if "path" in ci and not lib.is_path_value(ci["path"]):
                raise lib.RecipeError(f"{where}.path: an absolute path")
            if "check" in ci:
                for name in ("port", "proto", "group", "path"):
                    if "{{" + name + "}}" in variant["run"] and name not in ci:
                        raise lib.RecipeError(f"{where}: a {{{{{name}}}}} recipe needs ci.{name} to test with")


AGENT_URL = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://")


def check_agent_lines(doc):
    """The repository's own rules for the lines that install agent CLIs and herdr (docs/recipes-v3-plan.md 3.5): no
    privilege (the app drops a privileged one), https only, and an official installer is downloaded to
    ~/.mt-install-<name>.sh, run, and removed (never /tmp, never piped into a shell). Codex keeps its non-interactive
    switch."""
    for intent, variants in doc["intents"].items():
        if not (intent.startswith("agent.") or intent == "herdr.install"):
            continue
        name = "herdr" if intent == "herdr.install" else intent.split(".")[1]
        official = intent == "herdr.install" or intent.endswith(".install-official")
        for index, variant in enumerate(variants):
            where = f"{intent}[{index}]"
            run = variant["run"]
            if "{{sudo}}" in run or variant.get("admin") is True:
                raise lib.RecipeError(f"{where}: an agent or herdr install never needs an administrator")
            for match in AGENT_URL.finditer(run):
                if not run.startswith("https://", match.start()):
                    raise lib.RecipeError(f"{where}: every URL is https://")
            if "/tmp" in run:
                raise lib.RecipeError(f"{where}: never /tmp (another user can replace the file)")
            if re.search(r"\|\s*(?:sh|bash|zsh)\b", run):
                raise lib.RecipeError(f"{where}: never pipe a download into a shell")
            if official:
                script = f"~/.mt-install-{name}.sh"
                if f"-o {script}" not in run or not run.endswith(f"&& rm -f {script}"):
                    raise lib.RecipeError(f"{where}: download with -o {script}, run it, and end with && rm -f {script}")
            if intent == "agent.codex.install-official" and "CODEX_NON_INTERACTIVE=1" not in run:
                raise lib.RecipeError(f"{where}: keeps CODEX_NON_INTERACTIVE=1")


def selector_of(variant):
    versions = variant.get("versions", {})
    return (tuple(sorted(variant["families"])), tuple(sorted(variant.get("ids", []))), versions.get("min", ""),
            versions.get("below", ""))


def selector_json(selector):
    families, ids, low, high = selector
    out = {"families": list(families)}
    if ids:
        out["ids"] = list(ids)
    versions = {k: v for k, v in (("min", low), ("below", high)) if v}
    if versions:
        out["versions"] = versions
    return out


def data_changes(doc, expected):
    """Every app-visible difference between two documents (ci blocks are the CI's and ignored): (intent, selector) for
    a variant added, removed or changed, and ("package", id, family) for a package-table entry."""
    out = set()
    for intent in set(doc["intents"]) | set(expected["intents"]):
        mine = {selector_of(v): v for v in doc["intents"].get(intent, [])}
        theirs = {selector_of(v): v for v in expected["intents"].get(intent, [])}
        for selector in set(mine) | set(theirs):
            a, b = mine.get(selector), theirs.get(selector)
            strip = lambda v: None if v is None else {k: x for k, x in v.items() if k != "ci"}  # noqa: E731
            if strip(a) != strip(b):
                out.add(("intent", intent, selector))
    for package in set(doc["packages"]) | set(expected["packages"]):
        mine, theirs = doc["packages"].get(package, {}), expected["packages"].get(package, {})
        for family in set(mine) | set(theirs):
            if mine.get(family) != theirs.get(family):
                out.add(("package", package, family))
    return out


def check_declared(doc, previous, baseline, declared):
    """docs/recipes-v3-plan.md 6.3: `doc` against `previous` plus the baseline's NEW intents and package ids (the
    app's code text, moved as it was): every difference is in `declared`, and every declared change is there."""
    expected = {"intents": dict(previous["intents"]), "packages": dict(previous["packages"])}
    for intent, variants in baseline["intents"].items():
        if intent not in previous["intents"]:
            expected["intents"][intent] = variants
    for package, names in baseline["packages"].items():
        if package not in previous["packages"]:
            expected["packages"][package] = names
    changes = data_changes(doc, expected)
    listed = set()
    for entry in declared.get("changes", []):
        if not isinstance(entry, dict) or not isinstance(entry.get("reason"), str) or not entry["reason"].strip():
            raise lib.RecipeError(f"declared entry {entry!r}: needs a reason")
        if "package" in entry:
            key = ("package", entry["package"], entry.get("family"))
        else:
            selector = entry.get("selector", {})
            versions = selector.get("versions", {})
            key = ("intent", entry.get("intent"), (tuple(sorted(selector.get("families", []))),
                                                   tuple(sorted(selector.get("ids", []))),
                                                   versions.get("min", ""), versions.get("below", "")))
        if key in listed:
            raise lib.RecipeError(f"declared twice: {key}")
        listed.add(key)
    undeclared = sorted(changes - listed, key=str)
    missing = sorted(listed - changes, key=str)
    if undeclared:
        kind, a, b = undeclared[0]
        what = f"package {a} on {b}" if kind == "package" else f"{a} {selector_json(b)}"
        raise lib.RecipeError(f"{len(undeclared)} undeclared change(s), first: {what}")
    if missing:
        kind, a, b = missing[0]
        what = f"package {a} on {b}" if kind == "package" else f"{a} {selector_json(b)}"
        raise lib.RecipeError(f"{len(missing)} declared change(s) not in the file, first: {what}")
    return len(changes)


def git_show(ref, path):
    try:
        return subprocess.run(["git", "-C", ROOT, "show", f"{ref}:{path}"], check=True, capture_output=True).stdout
    except subprocess.CalledProcessError:
        return None


def validate(data, previous=None, need_ci=True):
    doc = lib.load(data)
    if need_ci:
        check_ci(doc)
        check_agent_lines(doc)
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


def run_format_cases():
    """ci/format-cases.json, the table meshTerm's HostRecipesTests run too. Returns the number of failures."""
    with open(FORMAT_CASES) as handle:
        cases = json.load(handle)
    failures = 0

    def file_with(intent, variants):
        return json.dumps({"kind": "host-recipes", "schema": 1, "serial": 1, "date": "2026-10-12", "packages": {},
                           "intents": {intent: variants}}).encode()

    def outcome(intent, variant):
        try:
            doc = lib.load(file_with(intent, [variant]))
        except lib.RecipeError:
            return "refused"
        return "ok" if lib.is_usable(doc, intent, 0) else "unusable"

    for case in cases["templates"]:
        intent = case.get("intent", "x.y")
        got = outcome(intent, {"families": ["apt"], "run": case["run"]})
        if got != case["result"]:
            print(f"self-test FAIL: template {case['run']!r} in {intent}: {got}, expected {case['result']}")
            failures += 1
    for case in cases["variants"]:
        got = outcome("x.y", case["variant"])
        if got != case["result"]:
            print(f"self-test FAIL: variant {case['variant']!r}: {got}, expected {case['result']}")
            failures += 1
    for case in cases["renders"]:
        values = dict(case["values"])
        got = lib.render(case["run"], values.pop("sudo"), **values)
        if got != case["out"]:
            print(f"self-test FAIL: render {case['run']!r} {case['values']!r}: {got!r}, expected {case['out']!r}")
            failures += 1
    for case in cases["selection"]:
        doc = lib.load(file_with("x.y", case["variants"]))
        bundled = lib.load(file_with("x.y", case["bundled"])) if case["bundled"] else \
            {"intents": {}, lib.UNUSABLE: set()}
        os_ = case["os"]
        picked = lib.select(doc, "x.y", os_["family"], os_.get("id"), os_.get("versionID"), bundled=bundled)
        got = picked["run"] if picked else None
        if got != case["pick"]:
            print(f"self-test FAIL: selection {case.get('why', '')} {os_}: {got!r}, expected {case['pick']!r}")
            failures += 1
    return failures


def self_test():
    with open(os.path.join(ROOT, "recipes.json"), "rb") as handle:
        good = handle.read()
    base = json.loads(good)

    def variant_of(run, **extra):
        doc = json.loads(good)
        doc["intents"]["x.y"] = [dict({"families": ["apt"], "run": run, "ci": {"skip": "test"}}, **extra)]
        return json.dumps(doc).encode()

    def intent_of(intent, run, **extra):
        doc = json.loads(good)
        doc["intents"][intent] = [dict({"families": ["any"], "run": run, "ci": {"skip": "test"}}, **extra)]
        return json.dumps(doc).encode()

    official = "curl -fsSL https://example.com/install.sh -o ~/.mt-install-claude.sh && bash ~/.mt-install-claude.sh && rm -f ~/.mt-install-claude.sh"
    codex = "curl -fsSL https://example.com/i.sh -o ~/.mt-install-codex.sh && env CODEX_NON_INTERACTIVE=1 sh ~/.mt-install-codex.sh && rm -f ~/.mt-install-codex.sh"
    bad = {
        "literal sudo": variant_of("sudo apt-get install -y x"),
        "literal su": variant_of("su -c 'apk add x'"),
        "sudo mid-command": variant_of("echo {{sudo}}apt-get install -y x"),
        "newline": variant_of("a\nb"),
        "non-ASCII": variant_of("apt-get install -y t\u0430"),
        "a sudo path": variant_of("/usr/bin/sudo apt-get install -y x"),
        "a quoted su": variant_of("x && \"su\" -c y"),
        "doas": variant_of("doas apk add x"),
        "pkexec": variant_of("pkexec apt-get install -y x"),
        "run0": variant_of("run0 dnf install -y x"),
        "escaped sudo": variant_of("\\sudo apt-get install -y x"),
        "user in quotes": variant_of("echo \"{{user}}\""),
        "user glued": variant_of("usermod -aG docker x{{user}}"),
        "admin not bool": variant_of("a", admin=1),
        "empty versions": variant_of("a", versions={}),
        "inverted versions": variant_of("a", versions={"min": "24.04", "below": "22.04"}),
        "bad package name": json.dumps(dict(base, packages=dict(base["packages"], curl={"apt": "Curl"}))).encode(),
        "wrong kind": json.dumps(dict(base, kind="templates")).encode(),
        "schema 2": json.dumps(dict(base, schema=2)).encode(),
        "bool serial": json.dumps(dict(base, serial=True)).encode(),
        "bad date": json.dumps(dict(base, date="2026-13-01")).encode(),
        "duplicate key": good.replace(b'"kind": "host-recipes",', b'"kind": "host-recipes", "kind": "host-recipes",', 1),
        "ci port out of range": variant_of("{{sudo}}ufw allow {{port}}/{{proto}}", ci={"check": "true", "port": 0, "proto": "udp"}),
        "ci without a port": variant_of("{{sudo}}ufw allow {{port}}/{{proto}}", ci={"check": "true", "proto": "udp"}),
        "agent with sudo": intent_of("agent.claude.install-npm", "{{sudo}}npm install -g x"),
        "agent admin": intent_of("agent.claude.install-npm", "npm install -g x", admin=True),
        "agent over http": intent_of("agent.claude.install-official", official.replace("https://", "http://")),
        "agent piped": intent_of("agent.claude.install-official", "curl -fsSL https://example.com/i.sh | sh"),
        "agent in /tmp": intent_of("agent.claude.install-official", official.replace("~/.mt-install-claude.sh", "/tmp/i.sh")),
        "agent not removed": intent_of("agent.claude.install-official", official.rsplit(" && ", 1)[0]),
        "codex interactive": intent_of("agent.codex.install-official", codex.replace("env CODEX_NON_INTERACTIVE=1 ", "")),
        "herdr piped": intent_of("herdr.install", "curl -fsSL https://herdr.dev/install.sh | bash"),
    }
    failures = run_format_cases()
    for name, data in bad.items():
        try:
            validate(data)
            print(f"self-test FAIL: '{name}' was accepted")
            failures += 1
        except lib.RecipeError:
            pass
    for name, data in {"agent official": intent_of("agent.claude.install-official", official),
                       "codex official": intent_of("agent.codex.install-official", codex),
                       "agent npm": intent_of("agent.codex.install-npm", 'npm install -g --prefix "$HOME/.local" @openai/codex')}.items():
        try:
            validate(data)
        except lib.RecipeError as error:
            print(f"self-test FAIL: '{name}' was refused: {error}")
            failures += 1
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
    # An unusable family-level variant still covers its family (the bundled one serves it).
    later = json.loads(good)
    later["serial"] += 1
    later["intents"]["tmux.install"][0]["init"] = "openrc"
    try:
        validate(json.dumps(later).encode(), previous=good)
    except lib.RecipeError as error:
        print(f"self-test FAIL: an unusable family variant does not cover: {error}")
        failures += 1
    try:
        validate(good, previous=good)
    except lib.RecipeError as error:
        print(f"self-test FAIL: the committed file is refused: {error}")
        failures += 1
    # The declared-changes check: one undeclared change fails; declared, it passes; a stale declaration fails.
    previous = lib.load(good)
    changed = json.loads(good)
    changed["intents"]["tmux.install"][0]["run"] = "{{sudo}}apt-get update && {{sudo}}apt-get install -y --no-install-recommends tmux"
    changed["intents"]["new.intent"] = [{"families": ["any"], "run": "echo new"}]
    baseline = {"intents": {"new.intent": [{"families": ["any"], "run": "echo new"}]}, "packages": {}}
    entry = {"intent": "tmux.install", "selector": {"families": ["apt"]}, "reason": "test"}
    current = lib.load(json.dumps(changed).encode())
    for name, declared, ok in [("undeclared", {"changes": []}, False), ("declared", {"changes": [entry]}, True),
                               ("stale", {"changes": [entry, dict(entry, intent="git.install")]}, False)]:
        try:
            check_declared(current, previous, baseline, declared)
            if not ok:
                print(f"self-test FAIL: declared check '{name}' passed")
                failures += 1
        except lib.RecipeError as error:
            if ok:
                print(f"self-test FAIL: declared check '{name}' failed: {error}")
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
    parser.add_argument("--declared", help="a declared-changes file: every data change against the previous file "
                                           "(plus --baseline's new intents and package ids) must be listed there")
    parser.add_argument("--baseline", help="with --declared: the app's code text as a recipes file (new intents)")
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
    if args.declared:
        if previous is None or not args.baseline:
            print("::error::--declared needs --baseline and --previous-ref or --previous-file")
            return 1
        try:
            with open(args.baseline, "rb") as handle:
                baseline = lib.load(handle.read())
            with open(args.declared) as handle:
                declared = json.load(handle)
            count = check_declared(doc, lib.load(previous), baseline, declared)
        except (lib.RecipeError, ValueError) as error:
            print(f"::error::declared changes: {error}")
            return 1
        print(f"declared changes: OK ({count} change(s), each declared)")
    for intent, index in lib.unusable_variants(doc):
        print(f"note: {intent}[{index}] is for a later app (unusable here; its bundled line serves this format)")
    variants = sum(len(v) for v in doc["intents"].values())
    print(f"OK: serial {doc['serial']} ({doc['date']}), {len(doc['intents'])} intents, {variants} variants, "
          f"{len(doc['packages'])} packages")
    return 0


if __name__ == "__main__":
    sys.exit(main())
