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
            if "windows" in variant["families"]:
                if not official:
                    raise lib.RecipeError(f"{where}: only an official installer (or herdr's) has a Windows line")
                check_windows_install(where, run, name, variant)
                continue
            if official:
                script = f"~/.mt-install-{name}.sh"
                if f"-o {script}" not in run or not run.endswith(f"&& rm -f {script}"):
                    raise lib.RecipeError(f"{where}: download with -o {script}, run it, and end with && rm -f {script}")
            if intent == "agent.codex.install-official" and "CODEX_NON_INTERACTIVE=1" not in run:
                raise lib.RecipeError(f"{where}: keeps CODEX_NON_INTERACTIVE=1")


# Serial 10 (meshTerm review): a Windows installer line is not checked for ingredients but BUILT: it must equal
# `windows_install_line(<name>)`, so a check moved after the run, commented out or short-circuited, another host or
# scheme, `curl -k`, dot-sourcing, elevation or an in-memory download can't pass. The vendor URL and the script's
# first token are allowlisted per installer (measured 2026-10-15).
WINDOWS_INSTALLERS = {
    "herdr": ("https://herdr.dev/install.ps1", "[CmdletBinding"),
    "claude": ("https://claude.ai/install.ps1", "param("),
    "codex": ("https://chatgpt.com/codex/install.ps1", "[CmdletBinding"),
    "agy": ("https://antigravity.google/cli/install.ps1", "$ErrorActionPreference"),
}
WINDOWS_INSTALL_INTENTS = {
    "herdr.install",
    "agent.claude.install-official",
    "agent.codex.install-official",
    "agent.agy.install-official",
}
NOT_A_SCRIPT = ("The installer download was not a script (the vendor server returned something else): "
                "tap again in a minute.")
# Codex: OpenAI signs install.ps1 (Authenticode). Valid, the exact simple name, and the organisation in the subject,
# checked BEFORE anything runs; on failure the status and Windows' own message say why (a host missing the root
# reads UnknownError / NotTrusted, which "not signed by OpenAI" would misstate).
CODEX_SIGNATURE = ("$s = Get-AuthenticodeSignature -LiteralPath $f; if (($s.Status -ne 'Valid') -or "
                   "($null -eq $s.SignerCertificate) -or "
                   "($s.SignerCertificate.GetNameInfo('SimpleName', $false) -cne 'OpenAI OpCo, LLC') -or "
                   "(-not $s.SignerCertificate.Subject.Contains('O=\"OpenAI OpCo, LLC\"'))) { "
                   "Remove-Item -Force -ErrorAction SilentlyContinue -LiteralPath $f; [Console]::Error.WriteLine("
                   "'The Codex installer signature did not check out (' + $s.Status + ': ' + $s.StatusMessage + "
                   "'), so it was not run.'); exit 1 }; $env:CODEX_NON_INTERACTIVE = '1'; ")


def windows_install_line(name):
    """The one accepted Windows line for installer `name`: curl.exe (https only, redirects too) downloads the vendor's
    install.ps1 to a fresh, randomly named file in the user's own %TEMP% (3 tries), which must start with the vendor
    script's first token; codex's signature is checked; then it runs with -File under a process-scoped Bypass, is
    removed, and its code is the line's."""
    url, token = WINDOWS_INSTALLERS[name]
    extra = CODEX_SIGNATURE if name == "codex" else ""
    return (f"$f = Join-Path $env:TEMP ('mt-install-{name}-' + [guid]::NewGuid().ToString('N') + '.ps1'); "
            f"$ok = $false; for ($i = 0; $i -lt 3; $i++) {{ curl.exe -fsSL --proto =https --retry 3 -o $f {url}; "
            "if (($LASTEXITCODE -eq 0) -and (Test-Path -LiteralPath $f)) { "
            "$t = [IO.File]::ReadAllText($f).TrimStart([char]0xFEFF).TrimStart(); "
            f"if ($t.StartsWith('{token}')) {{ $ok = $true; break }} }}; Start-Sleep -Seconds 5 }}; "
            "if (-not $ok) { Remove-Item -Force -ErrorAction SilentlyContinue -LiteralPath $f; "
            f"[Console]::Error.WriteLine('{NOT_A_SCRIPT}'); exit 1 }}; "
            f"{extra}powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $f; $c = $LASTEXITCODE; "
            "Remove-Item -Force -ErrorAction SilentlyContinue -LiteralPath $f; exit $c")


def check_windows_install(where, run, name, variant):
    """A Windows install line (meshTerm 2.3.0+, PowerShell 5.1): family windows only, and exactly
    `windows_install_line(name)` (serial 10: built, not pattern-checked)."""
    if variant["families"] != ["windows"]:
        raise lib.RecipeError(f"{where}: a Windows line is family windows only")
    if name not in WINDOWS_INSTALLERS:
        raise lib.RecipeError(f"{where}: no Windows installer is allowlisted for {name}")
    if run != windows_install_line(name):
        raise lib.RecipeError(f"{where}: a Windows install line must be exactly windows_install_line({name!r})")


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


# The top-level keys every file has (the serial and date change with every publish); any OTHER top-level key is data
# an app may read (serial 11: `idLike`), so a change to it must be declared.
FIXED_TOP_LEVEL = {"kind", "schema", "serial", "date", "packages", "intents", lib.UNUSABLE}
DISTROS = os.path.join(ROOT, "compat", "distros.json")


def data_changes(doc, expected):
    """Every app-visible difference between two documents (ci blocks are the CI's and ignored): (intent, selector) for
    a variant added, removed or changed, ("package", id, family) for a package-table entry, and ("top", key, None)
    for a top-level key other than the fixed ones (`idLike`) added, removed or changed."""
    out = set()
    for key in (set(doc) | set(expected)) - FIXED_TOP_LEVEL:
        if doc.get(key) != expected.get(key):
            out.add(("top", key, None))
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


# From this serial on (the first with a top-level `idLike`), --declared needs compat/distros.json: without it a newly
# named (or no longer named) inheritor would pass unnoticed.
ID_LIKE_SERIAL = 11


def inheritors(path=DISTROS):
    """The distro ids compat/distros.json lists with an ID_LIKE (`idLike`), less the ids the app's classifier names
    (those never inherit, named or not): hosts whose inheritance a newly named or no longer named id changes. None
    when the file is not there (it comes with the recipes-watch tooling)."""
    if not os.path.exists(path):
        return None
    with open(path) as handle:
        rows = json.load(handle).get("distros", [])
    return {row["id"] for row in rows if isinstance(row, dict) and row.get("id") and row.get("idLike")} \
        - set(lib.CONTAINERS_CLASSIFIER_IDS)


def declared_inheritors(doc, path=DISTROS):
    """`inheritors(path)` for a --declared run. A file of serial ID_LIKE_SERIAL or later without compat/distros.json
    is an error (RecipeError), never a skipped check; an earlier one gets None (and a note)."""
    inheriting = inheritors(path)
    if inheriting is None and doc["serial"] >= ID_LIKE_SERIAL:
        raise lib.RecipeError(f"no {path}: serial {doc['serial']} needs it to check newly named and no longer named "
                              "ID_LIKE inheritors (pass --distros)")
    return inheriting


def newly_named(doc, previous):
    return lib.named_ids(doc) - lib.named_ids(previous)


def no_longer_named(doc, previous):
    return lib.named_ids(previous) - lib.named_ids(doc)


def describe(change):
    kind, a, b = change
    if kind == "package":
        return f"package {a} on {b}"
    if kind == "top":
        return f"top-level {a}"
    if kind == "named":
        return f"{a} newly named (it is an inheritor in compat/distros.json: naming it stops its ID_LIKE inheritance)"
    if kind == "unnamed":
        return f"{a} no longer named (it is an inheritor in compat/distros.json: it now inherits through ID_LIKE)"
    return f"{a} {selector_json(b)}"


def check_declared(doc, previous, baseline, declared, inheriting=None):
    """docs/recipes-v3-plan.md 6.3: `doc` against `previous` plus the baseline's NEW intents and package ids (the
    app's code text, moved as it was): every difference is in `declared`, and every declared change is there.

    Entries: {"intent", "selector"} for a variant, {"package", "family"} for a package-table entry, {"kind": <key>}
    for a top-level key (`{"kind": "idLike"}`), and {"named": <id>} for a distro id the file names for the first time
    that `inheriting` (compat/distros.json's derivatives with an ID_LIKE) expects to inherit: a named id never
    inherits (docs/container-idlike-alpine-plan.md 9.2), so naming one in any intent silently moves EVERY intent of
    that host off its parent's lines; the declaration says that is meant. {"unnamed": <id>} is the reverse: an
    inheritor the previous file named and this one no longer does now STARTS inheriting its parent's lines."""
    expected = {"intents": dict(previous["intents"]), "packages": dict(previous["packages"])}
    expected.update({k: v for k, v in previous.items() if k not in FIXED_TOP_LEVEL})
    for intent, variants in baseline["intents"].items():
        if intent not in previous["intents"]:
            expected["intents"][intent] = variants
    for package, names in baseline["packages"].items():
        if package not in previous["packages"]:
            expected["packages"][package] = names
    changes = data_changes(doc, expected)
    if inheriting:
        changes |= {("named", i, None) for i in newly_named(doc, previous) & inheriting}
        changes |= {("unnamed", i, None) for i in no_longer_named(doc, previous) & inheriting}
    listed = set()
    for entry in declared.get("changes", []):
        if not isinstance(entry, dict) or not isinstance(entry.get("reason"), str) or not entry["reason"].strip():
            raise lib.RecipeError(f"declared entry {entry!r}: needs a reason")
        if "package" in entry:
            key = ("package", entry["package"], entry.get("family"))
        elif "kind" in entry:
            key = ("top", entry["kind"], None)
        elif "named" in entry:
            key = ("named", entry["named"], None)
        elif "unnamed" in entry:
            key = ("unnamed", entry["unnamed"], None)
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
        raise lib.RecipeError(f"{len(undeclared)} undeclared change(s), first: {describe(undeclared[0])}")
    if missing:
        raise lib.RecipeError(f"{len(missing)} declared change(s) not in the file, first: {describe(missing[0])}")
    return len(changes)


def git_show(ref, path):
    try:
        return subprocess.run(["git", "-C", ROOT, "show", f"{ref}:{path}"], check=True, capture_output=True).stdout
    except subprocess.CalledProcessError:
        return None


def check_windows_families(doc):
    """A `windows` variant is family windows ONLY, in every intent (serial 9 follow-up a): its line is PowerShell, so
    sharing a variant with a POSIX family would hand one of them a line in the wrong language. Serial 11: only the
    explicitly allowlisted install intents may have Windows variants."""
    for intent, variants in doc["intents"].items():
        for index, variant in enumerate(variants):
            if "windows" not in variant["families"]:
                continue
            if variant["families"] != ["windows"]:
                raise lib.RecipeError(f"{intent}[{index}]: a Windows line is family windows only")
            if intent not in WINDOWS_INSTALL_INTENTS:
                raise lib.RecipeError(f"{intent}[{index}]: no Windows installer is allowlisted for this intent")


def validate(data, previous=None, need_ci=True):
    doc = lib.load(data)
    check_windows_families(doc)
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


# The intent a selection case asks for when it names none (meshTerm's HostRecipesV3Tests uses the same one).
SELECTION_INTENT = "engine.podman.install"


def run_format_cases():
    """ci/format-cases.json, the table meshTerm's HostRecipesTests run too. Returns the number of failures."""
    with open(FORMAT_CASES) as handle:
        cases = json.load(handle)
    failures = 0

    def file_with(intent, variants, top=None, other_ids=None):
        intents = {intent: variants}
        if other_ids:
            intents["z.z"] = [{"families": ["any"], "ids": other_ids, "run": "other"}]
        return json.dumps(dict({"kind": "host-recipes", "schema": 1, "serial": 1, "date": "2026-10-12",
                                "packages": {}, "intents": intents}, **(top or {}))).encode()

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
    if cases.get("familyRoots") != sorted(lib.ID_LIKE_FAMILY_ROOTS):
        print(f"self-test FAIL: familyRoots {cases.get('familyRoots')!r} is not recipes_lib.ID_LIKE_FAMILY_ROOTS")
        failures += 1
    id_like_intents = cases.get("idLikeIntents", {})
    if id_like_intents.get("patterns") != list(lib.ID_LIKE_INTENTS):
        print(f"self-test FAIL: idLikeIntents.patterns {id_like_intents.get('patterns')!r} is not "
              "recipes_lib.ID_LIKE_INTENTS")
        failures += 1
    for intent, want in sorted(id_like_intents.get("examples", {}).items()):
        if lib.inherits_id_like(intent) != want:
            print(f"self-test FAIL: idLikeIntents example {intent}: expected {want}")
            failures += 1
    for case in cases["selection"]:
        # The intent asked (default: a Containers intent, which takes the parent); `parent` is the document-level
        # parent, passed to the lookup only for an ID_LIKE intent (HostRecipeStore.command).
        intent = case.get("intent", SELECTION_INTENT)
        top = {"idLike": case["idLike"]} if "idLike" in case else None
        doc = lib.load(file_with(intent, case["variants"], top, case.get("otherIds")))
        bundled_top = {"idLike": case["bundledIdLike"]} if "bundledIdLike" in case else None
        bundled = lib.load(file_with(intent, case["bundled"], bundled_top)) if case["bundled"] else \
            {"intents": {}, lib.UNUSABLE: set()}
        os_ = case["os"]
        parent = lib.parent(doc, os_.get("id"), os_.get("idLike", []), case.get("classifierIds", ()))
        if "parent" in case and parent != case["parent"]:
            print(f"self-test FAIL: parent {case.get('why', '')} {os_}: {parent!r}, expected {case['parent']!r}")
            failures += 1
        family, inherit, inherited = lib.recipe_os(doc, intent, os_["family"], os_.get("id"), os_.get("idLike", []),
                                                   case.get("classifierIds", ()), case.get("parentFamilies"))
        picked = lib.select(doc, intent, family, os_.get("id"), os_.get("versionID"), bundled=bundled,
                            parent_id=inherit, family_inherited=inherited)
        got = picked["run"] if picked else None
        if got != case["pick"]:
            print(f"self-test FAIL: selection {case.get('why', '')} {os_}: {got!r}, expected {case['pick']!r}")
            failures += 1
    for case in cases["documents"]:
        try:
            lib.load(file_with("x.y", [{"families": ["apt"], "run": "a"}], {"idLike": case["idLike"]}))
            got = "ok"
        except lib.RecipeError:
            got = "refused"
        if got != case["result"]:
            print(f"self-test FAIL: document idLike {case['idLike']!r}: {got}, expected {case['result']}")
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

    WIN_HERDR = windows_install_line("herdr")
    WIN_CODEX = windows_install_line("codex")
    run_at = "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $f;"
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
        "idLike not a list": json.dumps(dict(base, idLike="arch")).encode(),
        "idLike bad token": json.dumps(dict(base, idLike=["Arch"])).encode(),
        "idLike repeated": json.dumps(dict(base, idLike=["arch", "arch"])).encode(),
        "idLike too long": json.dumps(dict(base, idLike=[f"d{i}" for i in range(17)])).encode(),
        "duplicate key": good.replace(b'"kind": "host-recipes",', b'"kind": "host-recipes", "kind": "host-recipes",', 1),
        "windows beside a POSIX family": intent_of("herdr.install", WIN_HERDR, families=["windows", "apt"]),
        "windows beside POSIX in any intent": intent_of("tmux.install", "echo x", families=["windows", "any"]),
        "windows on a non-agent intent": intent_of("tmux.install", WIN_HERDR, families=["windows"]),
        "windows on an unknown intent": intent_of("x.y", WIN_HERDR, families=["windows"]),
        "windows on an unknown official agent": intent_of("agent.other.install-official", WIN_HERDR,
                                                          families=["windows"]),
        "windows on a lookalike official intent": intent_of("agent.claude.extra.install-official",
            windows_install_line("claude"), families=["windows"]),
        "windows iex": intent_of("herdr.install", WIN_HERDR.replace(run_at, run_at + " iex x;"), families=["windows"]),
        "windows not removed": intent_of("herdr.install", WIN_HERDR.replace("Remove-Item", "Rename-Item"), families=["windows"]),
        "windows removal without LiteralPath": intent_of("herdr.install", WIN_HERDR.replace("-LiteralPath $f;", "$f;"),
                                                         families=["windows"]),
        "codex signature without LiteralPath": intent_of("agent.codex.install-official", WIN_CODEX.replace(
            "Get-AuthenticodeSignature -LiteralPath", "Get-AuthenticodeSignature -FilePath"), families=["windows"]),
        "windows over http": intent_of("herdr.install", WIN_HERDR.replace("https://", "http://"), families=["windows"]),
        "windows scheme-less URL": intent_of("herdr.install", WIN_HERDR.replace("https://herdr.dev", "herdr.dev"), families=["windows"]),
        "windows curl -k": intent_of("herdr.install", WIN_HERDR.replace("curl.exe -fsSL", "curl.exe -k -fsSL"), families=["windows"]),
        "windows without --proto": intent_of("herdr.install", WIN_HERDR.replace("--proto =https ", ""), families=["windows"]),
        "windows another host": intent_of("herdr.install", WIN_HERDR.replace("herdr.dev", "herdr.example"), families=["windows"]),
        "windows fixed temp name": intent_of("herdr.install", WIN_HERDR.replace(
            "('mt-install-herdr-' + [guid]::NewGuid().ToString('N') + '.ps1')", "'mt-install-herdr.ps1'"), families=["windows"]),
        "windows dot-sourced": intent_of("herdr.install", WIN_HERDR.replace(run_at, ". $f; # " + run_at), families=["windows"]),
        "windows elevated": intent_of("herdr.install", WIN_HERDR.replace(
            run_at, "Start-Process powershell.exe -Verb RunAs -ArgumentList '-File', $f;"), families=["windows"]),
        "windows in-memory": intent_of("herdr.install", WIN_HERDR.replace(run_at, "& ([scriptblock]::Create((New-Object "
            "Net.WebClient).DownloadString('https://herdr.dev/install.ps1')));"), families=["windows"]),
        "windows looser first token": intent_of("herdr.install", WIN_HERDR.replace(
            "$t.StartsWith('[CmdletBinding')", "$t.StartsWith('[CmdletBinding') -or $t.StartsWith('#')"), families=["windows"]),
        "codex signature after the run": intent_of("agent.codex.install-official", WIN_CODEX.replace(CODEX_SIGNATURE, "")
            .replace("exit $c", CODEX_SIGNATURE + "exit $c"), families=["windows"]),
        "codex signature commented out": intent_of("agent.codex.install-official", WIN_CODEX.replace(
            "$s = Get-AuthenticodeSignature", "# $s = Get-AuthenticodeSignature"), families=["windows"]),
        "codex signature short-circuited": intent_of("agent.codex.install-official", WIN_CODEX.replace(
            "if (($s.Status -ne 'Valid')", "if ($false -and ($s.Status -ne 'Valid')"), families=["windows"]),
        "codex signer case-insensitive": intent_of("agent.codex.install-official", WIN_CODEX.replace(" -cne ", " -ne "),
                                                   families=["windows"]),
        "codex interactive": intent_of("agent.codex.install-official", WIN_CODEX.replace(
            "$env:CODEX_NON_INTERACTIVE = '1'; ", ""), families=["windows"]),
        "claude line under codex": intent_of("agent.codex.install-official", windows_install_line("claude"),
                                             families=["windows"]),
        "a Windows installer nobody allowlisted": intent_of("agent.claude.install-npm", "x", families=["windows"]),
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
    for name, data in {"codex windows": intent_of("agent.codex.install-official", WIN_CODEX, families=["windows"]),
                       "herdr windows": intent_of("herdr.install", WIN_HERDR, families=["windows"]),
                       "claude windows": intent_of("agent.claude.install-official", windows_install_line("claude"),
                                                    families=["windows"]),
                       "agy windows": intent_of("agent.agy.install-official", windows_install_line("agy"),
                                                 families=["windows"]),
                       "agent official": intent_of("agent.claude.install-official", official),
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
    # Serial 11: the top-level idLike is a declared change ({"kind": "idLike"}); a newly named inheritor too.
    allowlist = json.loads(good)
    allowlist["idLike"] = ["arch"]
    current = lib.load(json.dumps(allowlist).encode())
    top = {"kind": "idLike", "reason": "test"}
    for name, declared, ok in [("idLike undeclared", {"changes": []}, False),
                               ("idLike declared", {"changes": [top]}, True)]:
        try:
            check_declared(current, previous, {"intents": {}, "packages": {}}, declared)
            if not ok:
                print(f"self-test FAIL: declared check '{name}' passed")
                failures += 1
        except lib.RecipeError as error:
            if ok:
                print(f"self-test FAIL: declared check '{name}' failed: {error}")
                failures += 1
    try:
        check_declared(previous, previous, {"intents": {}, "packages": {}}, {"changes": [top]})
        print("self-test FAIL: a stale idLike declaration passed")
        failures += 1
    except lib.RecipeError:
        pass
    named = json.loads(good)
    named["intents"]["tmux.install"].append({"families": ["unknown"], "ids": ["newderiv"], "run": "echo x"})
    named_doc = lib.load(json.dumps(named).encode())
    entry = {"intent": "tmux.install", "selector": {"families": ["unknown"], "ids": ["newderiv"]}, "reason": "test"}
    for name, inheriting, declared, ok in [
            ("named inheritor undeclared", {"newderiv"}, [entry], False),
            ("named inheritor declared", {"newderiv"}, [entry, {"named": "newderiv", "reason": "meant"}], True),
            ("named, not an inheritor", {"otherderiv"}, [entry], True),
            ("named, no distros file", None, [entry], True),
            ("stale named declaration", {"otherderiv"}, [entry, {"named": "newderiv", "reason": "x"}], False)]:
        try:
            check_declared(named_doc, previous, {"intents": {}, "packages": {}}, {"changes": declared}, inheriting)
            if not ok:
                print(f"self-test FAIL: declared check '{name}' passed")
                failures += 1
        except lib.RecipeError as error:
            if ok:
                print(f"self-test FAIL: declared check '{name}' failed: {error}")
                failures += 1
    # The reverse: an inheritor the previous file named and this one does not now inherits ({"unnamed": id}).
    entry_back = {"intent": "tmux.install", "selector": {"families": ["unknown"], "ids": ["newderiv"]},
                  "reason": "test"}
    for name, inheriting, declared, ok in [
            ("unnamed inheritor undeclared", {"newderiv"}, [entry_back], False),
            ("unnamed inheritor declared", {"newderiv"}, [entry_back, {"unnamed": "newderiv", "reason": "meant"}],
             True),
            ("unnamed, not an inheritor", {"otherderiv"}, [entry_back], True),
            ("unnamed declared as named", {"newderiv"}, [entry_back, {"named": "newderiv", "reason": "x"}], False)]:
        try:
            check_declared(previous, named_doc, {"intents": {}, "packages": {}}, {"changes": declared}, inheriting)
            if not ok:
                print(f"self-test FAIL: declared check '{name}' passed")
                failures += 1
        except lib.RecipeError as error:
            if ok:
                print(f"self-test FAIL: declared check '{name}' failed: {error}")
                failures += 1
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".json") as handle:
        json.dump({"distros": [{"label": "a", "family": "unknown", "id": "manjaro", "idLike": ["arch"]},
                               {"label": "b", "family": "unknown", "id": "artix"},
                               {"label": "c", "family": "unknown", "id": "x", "idLike": []},
                               {"label": "d", "family": "apt", "id": "linuxmint", "idLike": ["ubuntu", "debian"]}]},
                  handle)
        handle.flush()
        if inheritors(handle.name) != {"manjaro"} or inheritors(handle.name + ".missing") is not None:
            print("self-test FAIL: inheritors() (a classifier id such as linuxmint never counts)")
            failures += 1
        # From serial 11 a --declared run without compat/distros.json fails; before it, a note.
        missing = handle.name + ".missing"
        try:
            declared_inheritors({"serial": ID_LIKE_SERIAL}, missing)
            print("self-test FAIL: --declared on a serial-11 file without compat/distros.json passed")
            failures += 1
        except lib.RecipeError:
            pass
        if declared_inheritors({"serial": ID_LIKE_SERIAL - 1}, missing) is not None \
                or declared_inheritors({"serial": ID_LIKE_SERIAL}, handle.name) != {"manjaro"}:
            print("self-test FAIL: declared_inheritors()")
            failures += 1
    # run-recipes.py's os-release parser (shell quoting).
    import importlib.util
    spec = importlib.util.spec_from_file_location("run_recipes", os.path.join(ROOT, "scripts", "run-recipes.py"))
    run_recipes = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(run_recipes)
    failures += run_recipes.self_test()
    # The parent's weights: an id 8, the parent 6 (never with a version range), a range 2, the family 1, any 0.
    arch, ver = {"families": ["unknown"], "ids": ["arch"], "run": "x"}, {"min": "1"}
    if lib.score(arch, "unknown", "arch") != 9 or lib.score(arch, "unknown", "x", None, "arch") != 7 \
            or lib.score(dict(arch, families=["any"]), "unknown", "x", None, "arch") != 6 \
            or lib.score(dict(arch, versions=ver), "unknown", "x", [2], "arch") is not None \
            or lib.score(dict(arch, versions=ver), "unknown", "arch", [2]) != 11 \
            or lib.score(arch, "unknown", "x", None, "debian") is not None:
        print("self-test FAIL: score()'s parent weights")
        failures += 1
    # parent(): the token equal to the host's own id is skipped; no ID_LIKE, no parent; the classifier names count.
    allow = {"idLike": ["arch", "debian"], "intents": {}}
    if lib.parent(allow, "arch", ["arch"]) is not None or lib.parent(allow, "x", []) is not None \
            or lib.parent(allow, "X", ["ARCH"]) != "arch" or lib.parent(allow, None, ["debian"]) != "debian" \
            or lib.parent(allow, "alpine", ["arch"], lib.CONTAINERS_CLASSIFIER_IDS) is not None:
        print("self-test FAIL: parent()")
        failures += 1
    # The Containers parent families are the classifier's families, id for id (ContainerHostOS.parentFamilies).
    if set(lib.CONTAINERS_PARENT_FAMILIES) != set(lib.CONTAINERS_CLASSIFIER_IDS):
        print("self-test FAIL: CONTAINERS_PARENT_FAMILIES is not keyed by CONTAINERS_CLASSIFIER_IDS")
        failures += 1
    # The resolver: an id variant beats the family; a range needs a VERSION_ID.
    doc = lib.load(good)
    ubuntu = lib.select(doc, "compose.install-package", "apt", "ubuntu")
    debian = lib.select(doc, "compose.install-package", "apt", "debian")
    if ubuntu is None or debian is not None:
        print("self-test FAIL: compose.install-package selection")
        failures += 1
    # score(): an `any` (POSIX) line never applies to a windows host, a windows line only to one (serial 9 follow-up b).
    if lib.score({"families": ["any"], "run": "x"}, "windows") is not None \
            or lib.score({"families": ["windows"], "run": "x"}, "windows") != 1 \
            or lib.score({"families": ["windows"], "run": "x"}, "apt") is not None \
            or lib.score({"families": ["any"], "run": "x"}, "apt") != 0:
        print("self-test FAIL: score()'s windows rules")
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
    parser.add_argument("--distros", default=DISTROS,
                        help="with --declared: the compat hosts; an id listed there with an idLike that is newly "
                             "named, or no longer named, must be declared ({\"named\": id} / {\"unnamed\": id}); "
                             f"required from serial {ID_LIKE_SERIAL}")
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
            inheriting = declared_inheritors(doc, args.distros)
            if inheriting is None:
                print(f"note: no {os.path.relpath(args.distros, ROOT)}: newly named inheritors are not checked "
                      f"(serial {doc['serial']} is below {ID_LIKE_SERIAL})")
            count = check_declared(doc, lib.load(previous), baseline, declared, inheriting)
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
