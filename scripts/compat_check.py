#!/usr/bin/env python3
"""Would every released app still read this recipes file, and run the right line? (the pre-sign compat gate)

The app source is private, so this repository cannot run the apps' readers. Instead each released reader is
described by a committed PROFILE, compat/<profile>.json: the schemas it reads, the placeholders it knows and where
they may go, the variant keys it knows and what it does with others, whether it honours `minSchema`, how it falls
back (its bundled snapshot, compat/bundled/), the intents it asks for and which placeholder values it passes. The
meshTerm side keeps each profile honest (RecipesCompatProfileTests checks its copy against the Swift reader).

For each profile this simulates that app with a candidate file:

  file level   accept or refuse, by that reader's rules (validation, rollback against its bundled copy and the
               previous file, same serial with different bytes, coverage of its bundled copy). FAIL when it would
               refuse a file it accepted before (`--previous`), or refuse one at or above its bundled serial.
  per intent   for every intent it asks for and every host in compat/distros.json: the variant it would select,
               or its bundled fallback, rendered with the values it passes. FAIL when it would run a line meant for
               a later app (a variant key it ignores, a `minSchema` it does not honour), when the command it ends up
               with is missing where the previous file gave one, when an unprivileged intent (agents, herdr) gets a
               privileged line the app then drops, or when a placeholder survives rendering.

    scripts/compat_check.py                                   # recipes.json against every profile
    scripts/compat_check.py --candidate F --previous P        # also: no regression against the deployed file
    scripts/compat_check.py --path v1/recipes.json            # only the profiles that fetch that path
    scripts/compat_check.py --json out.json --summary "$GITHUB_STEP_SUMMARY"
    scripts/compat_check.py --self-test

Exit 1 when a BLOCKING profile fails (a profile's `blocking`: App Store readers block, TestFlight-only ones warn).
"""
import argparse
import fnmatch
import glob
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import watch_results  # noqa: E402

TOKEN = re.compile(r"^[a-z0-9-]{1,32}$")
IDENTIFIER = re.compile(r"^[A-Za-z0-9]{1,32}$")
DISTRO_ID = re.compile(r"^[a-z0-9._-]{1,64}$")
PACKAGE = re.compile(r"^[a-z0-9][a-z0-9.+_-]{0,63}$")
INTENT = re.compile(r"^[a-z0-9]+(?:[.-][a-z0-9]+)*$")
DATE = re.compile(r"^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$")
WORD_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.")
SAMPLE = {"user": "mt", "packages": ["git"], "port": 22, "proto": "tcp", "path": "/usr/bin/rootlesskit",
          "rpmPackages": ["NetworkManager", "perl-DBI", "openssl-libs"]}
# Intents whose {{packages}} the app fills from the host's own rpm listing (meshTerm 2.4 S5,
# SecurityUpdatesPackagesSection), so the names can be capitalised whatever the reader accepts: rendered with
# SAMPLE["rpmPackages"]. Whether a reader TAKES them is the profile's placement.capitalisedPackageIntents (an exact
# intent, Swift's Set.contains) and rpmPackageName; any other intent's names must be PACKAGE
# (HostRecipeValues.value(for:rpmNames:)).
HOST_RPM_NAME_INTENTS = {"security-updates.dnf"}
RPM_PACKAGE = r"^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$"


class Refused(Exception):
    """The reader refuses the whole file (it keeps the copy it has)."""


def is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def parse_version(text):
    if not isinstance(text, str):
        return None
    parts = text.split(".")
    if not parts or len(parts) > 6 or any(not p.isdigit() or len(p) > 9 or not p.isascii() for p in parts):
        return None
    return [int(p) for p in parts]


def compare(a, b):
    for i in range(max(len(a), len(b))):
        x, y = (a[i] if i < len(a) else 0), (b[i] if i < len(b) else 0)
        if x != y:
            return -1 if x < y else 1
    return 0


def contains_word(text, word):
    start = text.find(word)
    while start >= 0:
        before = text[start - 1] if start > 0 else None
        after = text[start + len(word)] if start + len(word) < len(text) else None
        if (before is None or before not in WORD_CHARS) and (after is None or after not in WORD_CHARS):
            return True
        start = text.find(word, start + 1)
    return False


class Variant:
    def __init__(self, intent, index, raw, families, ids, low, high, run, admin, names, later, usable, extra_keys):
        self.intent, self.index, self.raw = intent, index, raw
        self.families, self.ids, self.low, self.high = families, ids, low, high
        self.run, self.admin, self.names, self.later = run, admin, names, later
        self.usable, self.extra_keys = usable, extra_keys

    @property
    def is_family_fallback(self):
        return self.ids is None and self.low is None and self.high is None

    def score(self, os_):
        exact = os_["family"] in self.families
        if not exact and "any" not in self.families:
            return None
        value = 1 if exact else 0
        if self.ids is not None:
            if not os_.get("id") or os_["id"] not in self.ids:
                return None
            value += 4
        if self.low is not None or self.high is not None:
            version = parse_version(os_.get("versionID"))
            if version is None:
                return None
            if self.low is not None and compare(version, parse_version(self.low)) < 0:
                return None
            if self.high is not None and compare(version, parse_version(self.high)) >= 0:
                return None
            value += 2
        return value


class Doc:
    def __init__(self, serial, packages, intents, body):
        self.serial, self.packages, self.intents, self.body = serial, packages, intents, body


class Reader:
    """One app version's recipes reader, from its profile (the Swift HostRecipeDocument / HostRecipeTemplate /
    HostRecipeStore rules, parameterised)."""

    def __init__(self, profile):
        self.profile = profile
        r = profile["reader"]
        self.r = r
        self.placeholders = set(r["placeholders"])
        self.variant_keys = set(r["variantKeys"])
        self.later_pattern = re.compile(r.get("laterPlaceholderPattern") or r"^\b$")

    # -- template -------------------------------------------------------------------------------------------------

    def parse_template(self, run, intent):
        r = self.r
        if not isinstance(run, str) or not run or len(run) > r["maxRun"]:
            raise Refused("empty or too long")
        if any(not (0x20 <= ord(c) <= 0x7E) for c in run):
            raise Refused("not printable ASCII on one line")
        names, later, plain, pos = [], [], "", 0
        while True:
            start = run.find("{{", pos)
            if start < 0:
                break
            plain += run[pos:start]
            end = run.find("}}", start + 2)
            if end < 0:
                raise Refused("unclosed {{")
            name, before = run[start + 2:end], run[:start]
            if name not in self.placeholders:
                if r["laterPlaceholders"] == "variant-unusable" and self.later_pattern.fullmatch(name):
                    later.append(name)
                else:
                    raise Refused(f"unknown placeholder {{{{{name}}}}}")
            elif name == "sudo":
                if before and not before.endswith(tuple(r["sudoOpeners"])):
                    raise Refused("{{sudo}} must open a command")
                after = run[end + 2:]
                if not after or after[0] == " ":
                    raise Refused("{{sudo}} needs a command after it")
            elif name == "group":
                if not before.endswith(tuple(r["placement"].get("group") or ["\0"])):
                    raise Refused("{{group}} misplaced")
            elif name == "packages" and self.packages_openers(intent) is not None:
                self.check_packages_placement(intent, before)
            if name in self.placeholders:
                names.append(name)
            plain += " "
            pos = end + 2
        plain += run[pos:]
        if "}}" in plain:
            raise Refused("stray }}")
        if names.count("packages") > 1:
            raise Refused("{{packages}} twice")
        for word in r["privilegeWords"]:
            if contains_word(plain, word):
                raise Refused(f"a literal {word}")
        for i, c in enumerate(run):
            if c == "\\" and ((i > 0 and run[i - 1].isalpha()) or (i + 1 < len(run) and run[i + 1].isalpha())):
                raise Refused("a backslash next to a letter")
        self.check_user_placement(run)
        return names, later

    @staticmethod
    def pattern_value(table, intent):
        """The value for `intent` in a placement table keyed by intent or fnmatch pattern (`security-updates.*`, app
        2.4: the Swift reader's prefix rule); an exact key wins. `_` keys are comments. None when nothing matches."""
        if not isinstance(table, dict) or intent is None:
            return None
        if intent in table:
            return table[intent]
        for pattern, value in table.items():
            if not pattern.startswith("_") and fnmatch.fnmatchcase(intent, pattern):
                return value
        return None

    def packages_openers(self, intent):
        return self.pattern_value(self.r["placement"].get("packagesByIntent"), intent)

    def check_packages_placement(self, intent, before):
        """{{packages}} for an intent with a placement rule (meshTerm HostRecipeTemplate): right after one of its
        openers (as whole words for a packagesWholeWord intent, 2.4), and (2.4, S4 review L6 / S5 app review L4) none
        of packagesNoInstallWordBefore's words anywhere before it, apart from the intent's packagesInstallWordException
        opener when the text ends with it."""
        placement = self.r["placement"]
        openers = tuple(self.packages_openers(intent))
        whole = any(fnmatch.fnmatchcase(intent, p) for p in placement.get("packagesWholeWord") or [])

        def ends_with(text, opener):
            if not text.endswith(opener):
                return False
            head = text[: len(text) - len(opener)]
            return not whole or head == "" or head.endswith(" ")
        if not any(ends_with(before, opener) for opener in openers):
            raise Refused(f"{{{{packages}}}} misplaced in {intent}")
        words = self.pattern_value(placement.get("packagesNoInstallWordBefore"), intent) or []
        exception = (placement.get("packagesInstallWordException") or {}).get(intent)
        head = before[: len(before) - len(exception)] if exception and ends_with(before, exception) else before
        for word in words:
            if contains_word(head, word):
                raise Refused(f"an install verb ({word}) before {{{{packages}}}} in {intent}")

    @staticmethod
    def check_user_placement(run):
        quote, i = None, 0
        while i < len(run):
            if run.startswith("{{user}}", i):
                before = run[i - 1] if i > 0 else None
                after = run[i + 8] if i + 8 < len(run) else None
                if quote is not None or (before is not None and before != " ") or \
                        (after is not None and after not in " ;&|)"):
                    raise Refused("{{user}} must be a word of its own, outside quotes")
                i += 8
                continue
            c = run[i]
            if quote is None and c in "'\"":
                quote = c
            elif quote is not None and c == quote:
                quote = None
            i += 1

    # -- document ---------------------------------------------------------------------------------------------------

    def decode(self, data):
        r = self.r
        if len(data) > r["maxBytes"]:
            raise Refused(f"too large ({len(data)} bytes)")
        try:
            raw = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise Refused("not JSON") from None
        if not isinstance(raw, dict):
            raise Refused("not a JSON object")
        if raw.get("kind") != r["kind"]:
            raise Refused(f"wrong kind {raw.get('kind')!r}")
        if not is_int(raw.get("schema")):
            raise Refused("schema")
        if raw["schema"] not in r["schemas"]:
            raise Refused(f"unsupported schema {raw['schema']}")
        serial, date, packages, intents = raw.get("serial"), raw.get("date"), raw.get("packages"), raw.get("intents")
        if not is_int(serial) or not isinstance(date, str) or not isinstance(packages, dict) \
                or not isinstance(intents, dict):
            raise Refused("malformed top level")
        if serial < 1:
            raise Refused("no valid serial")
        if not DATE.fullmatch(date):
            raise Refused("no valid date")
        for pid, names in packages.items():
            if not isinstance(names, dict) or not all(isinstance(v, str) for v in names.values()):
                raise Refused(f"wrong type at packages.{pid}")
            if not IDENTIFIER.fullmatch(pid):
                raise Refused(f"package {pid}")
            for family, name in names.items():
                if not TOKEN.fullmatch(family) or not PACKAGE.fullmatch(name):
                    raise Refused(f"package {pid} on {family}")
        if not intents:
            raise Refused("intents")
        out = {}
        for intent, items in intents.items():
            if not isinstance(items, list):
                raise Refused(f"wrong type at intents.{intent}")
            if not INTENT.fullmatch(intent) or len(intent) > 64 or not items:
                raise Refused(f"intent {intent}")
            variants, selectors = [], set()
            for index, item in enumerate(items):
                variant = self.make_variant(item, intent, index)
                selector = (tuple(sorted(variant.families)), tuple(sorted(variant.ids or [])), variant.low or "",
                            variant.high or "")
                if selector in selectors:
                    raise Refused(f"{intent}[{index}] repeats a selector")
                selectors.add(selector)
                variants.append(variant)
            out[intent] = variants
        return Doc(serial, packages, out, data)

    def make_variant(self, item, intent, index):
        r, place = self.r, f"{intent}[{index}]"
        if not isinstance(item, dict):
            raise Refused(f"wrong type at {place}")
        # Swift's decodeIfPresent reads an explicit null as absent; the key still counts for "a key this reader does
        # not know" (container.allKeys lists it).
        all_keys = set(item)
        item = {k: v for k, v in item.items() if not (v is None and k in ("ids", "versions", "admin", "minSchema"))}
        families, ids, versions, run = item.get("families"), item.get("ids"), item.get("versions"), item.get("run")
        honours_min = r["minSchema"] == "honoured"
        # JSONDecoder strictness on the keys this reader decodes.
        if not isinstance(families, list) or not all(isinstance(f, str) for f in families) or not isinstance(run, str):
            raise Refused(f"wrong type at {place}")
        if ids is not None and (not isinstance(ids, list) or not all(isinstance(i, str) for i in ids)):
            raise Refused(f"wrong type at {place}.ids")
        if versions is not None and (not isinstance(versions, dict) or
                                     any(not isinstance(versions.get(k), (str, type(None))) for k in ("min", "below"))):
            raise Refused(f"wrong type at {place}.versions")
        if "admin" in item and not isinstance(item["admin"], bool):
            raise Refused(f"wrong type at {place}.admin")
        if honours_min and "minSchema" in item and not is_int(item["minSchema"]):
            raise Refused(f"wrong type at {place}.minSchema")
        if not families or not all(TOKEN.fullmatch(f) for f in families) or len(set(families)) != len(families):
            raise Refused(f"{place}.families")
        if ids is not None and (not ids or not all(DISTRO_ID.fullmatch(i) for i in ids) or len(set(ids)) != len(ids)):
            raise Refused(f"{place}.ids")
        low = high = None
        if versions is not None:
            low, high = versions.get("min"), versions.get("below")
            if (low is None and high is None) or (low is not None and parse_version(low) is None) or \
                    (high is not None and parse_version(high) is None):
                raise Refused(f"{place}.versions")
            if low is not None and high is not None and compare(parse_version(low), parse_version(high)) >= 0:
                raise Refused(f"{place}.versions is empty")
        try:
            names, later = self.parse_template(run, intent)
        except Refused as error:
            raise Refused(f"{place}.run: {error}") from None
        if honours_min and "minSchema" in item and item["minSchema"] < 1:
            raise Refused(f"{place}.minSchema")
        extra = sorted(all_keys - self.variant_keys)
        usable = not later
        if extra and r["unknownVariantKeys"] == "variant-unusable":
            usable = False
        if honours_min and item.get("minSchema", 1) > r["supportedSchema"]:
            usable = False
        admin = item["admin"] if "admin" in item else ("sudo" in names)
        return Variant(intent, index, item, families, ids, low, high, run, admin, names, later, usable, extra)

    def evaluate(self, data, bundled, current):
        """HostRecipeStore.evaluate: the document, or Refused."""
        doc = self.decode(data)
        floor = max(bundled.serial, current.serial if current else 0)
        if doc.serial < floor:
            raise Refused(f"rollback: serial {doc.serial} is below {floor}")
        if doc.serial == bundled.serial and doc.body != bundled.body:
            raise Refused(f"serial {doc.serial} is the bundled serial with different bytes")
        if current and doc.serial == current.serial and doc.body != current.body:
            raise Refused(f"serial {doc.serial} is the current serial with different bytes")
        for intent, variants in bundled.intents.items():
            mine = doc.intents.get(intent)
            if mine is None:
                raise Refused(f"drops intent {intent} (the bundled copy has it)")
            needed = {f for v in variants if v.is_family_fallback for f in v.families}
            have = {f for v in mine if v.is_family_fallback for f in v.families}
            if needed - have:
                raise Refused(f"drops {intent} on {sorted(needed - have)[0]}")
        for package in bundled.packages:
            if package not in doc.packages:
                raise Refused(f"drops package {package}")
        return doc

    # -- selection and rendering --------------------------------------------------------------------------------------

    def selection(self, doc, intent, os_):
        best, best_score, blocked = None, None, None
        for variant in doc.intents.get(intent, []):
            score = variant.score(os_)
            if score is None:
                continue
            if not variant.usable:
                blocked = score if blocked is None else max(blocked, score)
                continue
            if best_score is None or score > best_score:
                best, best_score = variant, score
        if blocked is not None and self.r.get("unusableSelection") and (best_score is None or blocked >= best_score):
            return "bundled", None
        return ("variant", best) if best else ("none", None)

    def supplied(self, intent):
        out = {"sudo", "user"}
        for pattern, names in self.profile.get("supplies", {}).items():
            if not pattern.startswith("_") and fnmatch.fnmatchcase(intent, pattern):
                out |= set(names)
        return out

    def packages_value(self, intent, names=None):
        """{{packages}} as the app renders it for `intent` (HostRecipeValues.value(for:rpmNames:)): the names joined by
        spaces, or None (the line renders nil) when one breaks the reader's rule for this intent: rpmPackageName for
        a placement.capitalisedPackageIntents intent (2.4: security-updates.dnf), the lowercase PACKAGE otherwise.
        `names` defaults to the sample the app would pass: capitalised rpm names for a HOST_RPM_NAME_INTENTS intent."""
        if names is None:
            names = SAMPLE["rpmPackages"] if intent in HOST_RPM_NAME_INTENTS else SAMPLE["packages"]
        placement = self.r.get("placement") or {}
        if intent in (placement.get("capitalisedPackageIntents") or []):
            rule = re.compile(placement.get("rpmPackageName") or RPM_PACKAGE)
        else:
            rule = PACKAGE
        if not names or not all(rule.fullmatch(name) for name in names):
            return None
        return " ".join(names)

    def render(self, variant, intent, os_):
        if variant.later:
            return None
        supplied = self.supplied(intent)
        values = {"sudo": "sudo ", "user": SAMPLE["user"], "packages": self.packages_value(intent),
                  "port": str(SAMPLE["port"]), "proto": SAMPLE["proto"], "path": SAMPLE["path"],
                  "group": "sudo" if os_["family"] == "apt" else "wheel"}
        out, pos, run = "", 0, variant.run
        while True:
            start = run.find("{{", pos)
            end = run.find("}}", start + 2) if start >= 0 else -1
            if start < 0 or end < 0:
                break
            name = run[start + 2:end]
            if name not in supplied or values.get(name) is None:
                return None
            out += run[pos:start] + values[name]
            pos = end + 2
        return out + run[pos:]

    def command(self, doc, bundled, intent, os_):
        """HostRecipeStore.command: (text, variant, origin) where origin is file / bundled / render-fallback / none."""
        is_bundled = doc.serial == bundled.serial and doc.body == bundled.body

        def from_bundled(origin):
            if is_bundled:
                return None, None, "none"
            kind, fallback = self.selection(bundled, intent, os_)
            if kind != "variant":
                return None, None, "none"
            text = self.render(fallback, intent, os_)
            return (text, fallback, origin) if text is not None else (None, None, "none")

        kind, variant = self.selection(doc, intent, os_)
        if kind == "none":
            return None, None, "none"
        if kind == "bundled":
            return from_bundled("bundled")
        text = self.render(variant, intent, os_)
        return (text, variant, "file") if text is not None else from_bundled("render-fallback")


# ---------------------------------------------------------------------------------------------------------- checking

def load_profiles(directory, only=None):
    profiles = []
    for path in sorted(glob.glob(os.path.join(directory, "*.json"))):
        if os.path.basename(path) == "distros.json":
            continue
        with open(path) as handle:
            profile = json.load(handle)
        if only and profile["profile"] not in only:
            continue
        bundled_path = os.path.join(ROOT, profile["bundled"]["file"]) if not os.path.isabs(profile["bundled"]["file"]) \
            else profile["bundled"]["file"]
        with open(bundled_path, "rb") as handle:
            data = handle.read()
        if hashlib.sha256(data).hexdigest() != profile["bundled"]["sha256"]:
            raise SystemExit(f"{path}: {profile['bundled']['file']} does not match the profile's sha256")
        profile["_bundled_bytes"] = data
        profiles.append(profile)
    return profiles


def check_profile(profile, candidate, previous, distros):
    """Findings for one profile: a list of (status, kind, intent, detail). `status` is fail / info."""
    reader = Reader(profile)
    bundled = reader.decode(profile["_bundled_bytes"])
    findings = []
    prev_doc = None
    if previous is not None:
        try:
            prev_doc = reader.evaluate(previous, bundled, None)
        except Refused:
            prev_doc = None
    try:
        doc = reader.evaluate(candidate, bundled, prev_doc)
    except Refused as error:
        serial = None
        try:
            serial = json.loads(candidate.decode("utf-8")).get("serial")
        except (ValueError, UnicodeDecodeError, AttributeError):
            pass
        if prev_doc is not None:
            findings.append(("fail", "refuses-file", "", f"refuses the file it accepted before: {error}"))
        elif str(error).startswith("rollback") and is_int(serial) and serial < bundled.serial:
            findings.append(("info", "older-than-bundled", "", f"{error}: the app keeps its bundled serial "
                             f"{bundled.serial} (expected for a file older than this app)"))
        else:
            findings.append(("fail", "refuses-file", "", f"refuses the file: {error}"))
        return findings, None

    later_lines, missing, privileged, leftover, dead, absent = {}, {}, {}, {}, {}, []
    for intent in profile["intents"]:
        if intent not in doc.intents and intent not in bundled.intents:
            absent.append(intent)
            continue
        for os_ in distros:
            text, variant, origin = reader.command(doc, bundled, intent, os_)
            label = os_["label"]
            if origin == "file" and (variant.extra_keys or
                                     ("minSchema" in variant.raw and reader.r["minSchema"] != "honoured"
                                      and variant.raw.get("minSchema", 1) > reader.r["supportedSchema"])):
                why = ", ".join(variant.extra_keys) if variant.extra_keys else "minSchema"
                later_lines.setdefault((intent, variant.index, why), []).append(label)
            if origin == "render-fallback":
                dead.setdefault((intent, variant.index if variant else -1), []).append(label)
            if text is not None and ("{{" in text or "}}" in text):
                leftover.setdefault(intent, []).append(label)
            if text is not None and intent_matches(intent, profile.get("unprivilegedIntents", [])) \
                    and (variant.admin or "sudo" in variant.names):
                privileged.setdefault(intent, []).append(label)
            if text is None and prev_doc is not None:
                ptext, _, _ = reader.command(prev_doc, bundled, intent, os_)
                if ptext is not None:
                    missing.setdefault(intent, []).append(label)
    for (intent, index, why), hosts in sorted(later_lines.items()):
        findings.append(("fail", "later-line", intent, f"{intent}[{index}] has {why}, which this reader "
                         f"{'ignores' if why != 'minSchema' else 'does not honour'}: it would RUN that line (meant "
                         f"for a later app) on {', '.join(hosts)}"))
    for intent, hosts in sorted(missing.items()):
        findings.append(("fail", "drops-command", intent, f"no command any more on {', '.join(hosts)} (the previous "
                         "file had one)"))
    for intent, hosts in sorted(privileged.items()):
        findings.append(("fail", "privileged", intent, f"a privileged line ({{{{sudo}}}} or admin) for an "
                         f"unprivileged intent: the app drops it, so no install line on {', '.join(hosts)}"))
    for intent, hosts in sorted(leftover.items()):
        findings.append(("fail", "placeholder-left", intent, f"a placeholder survives rendering on {', '.join(hosts)}"))
    for (intent, index), hosts in sorted(dead.items()):
        findings.append(("info", "render-fallback", intent, f"{intent}[{index}] uses a placeholder this app does not "
                         f"pass for the intent: it uses its bundled line instead on {', '.join(hosts)}"))
    for intent in absent:
        findings.append(("info", "absent", intent, "the app asks for it; neither this file nor its bundled copy has it"))
    return findings, doc


def intent_matches(intent, patterns):
    return any(fnmatch.fnmatchcase(intent, p) for p in patterns)


def run(candidate_path, previous_path, profiles, distros, path=None, source="main", json_out=None, summary=None,
        quiet=False):
    with open(candidate_path, "rb") as handle:
        candidate = handle.read()
    previous = None
    if previous_path:
        with open(previous_path, "rb") as handle:
            previous = handle.read()
    selected = [p for p in profiles if path is None or path in p.get("fetchPaths", [])]
    result = watch_results.new("compat", source=source, recipes=candidate_path,
                               covers=[f"compat:{p['profile']}" for p in selected])
    blocking_failed, lines = False, []
    for profile in selected:
        findings, doc = check_profile(profile, candidate, previous, distros)
        fails = [f for f in findings if f[0] == "fail"]
        state = "FAIL" if fails else "PASS"
        accepted = "accepted" if doc else "refused"
        tag = "blocking" if profile["blocking"] else "non-blocking"
        lines.append(f"{state:<4} {profile['profile']} ({tag}): {accepted}, {len(fails)} failing finding(s)")
        for status, kind, intent, detail in findings:
            lines.append(f"     {status.upper():<4} {kind:<17} {intent or '(file)'}: {detail}")
            watch_results.add(result, f"compat:{profile['profile']}", status, intent or "(file)", kind,
                              detail=detail)
            if status == "fail":
                result["results"][-1]["label"] = "bug" if profile["blocking"] else "heads-up"
        if fails and profile["blocking"]:
            blocking_failed = True
    if not quiet:
        print(f"compat: {candidate_path}" + (f" (previous {previous_path})" if previous_path else ""))
        print("\n".join(lines))
    if json_out:
        watch_results.write(result, json_out)
    if summary:
        with open(summary, "a") as handle:
            handle.write(f"### App compatibility: `{os.path.basename(candidate_path)}`\n\n```\n" + "\n".join(lines)
                         + "\n```\n")
    return blocking_failed, result


# ---------------------------------------------------------------------------------------------------------- self-test

def self_test():
    import copy
    import tempfile

    profiles = load_profiles(os.path.join(ROOT, "compat"))
    by_name = {p["profile"]: p for p in profiles}
    with open(os.path.join(ROOT, "compat", "distros.json")) as handle:
        distros = json.load(handle)["distros"]
    s2 = json.loads(by_name["testflight-serial2"]["_bundled_bytes"])
    s3 = json.loads(by_name["app-2.3.0"]["_bundled_bytes"])

    def dump(doc):
        return doc if isinstance(doc, bytes) else json.dumps(doc, indent=1).encode()

    def bump(doc, serial):
        doc = copy.deepcopy(doc)
        doc["serial"] = serial
        return doc

    def kinds(name, candidate, previous=None):
        findings, doc = check_profile(by_name[name], dump(candidate), dump(previous) if previous else None, distros)
        return {(status, kind, intent) for status, kind, intent, _ in findings}, doc

    cases = []

    def case(label, got, want_present=(), want_absent=()):
        ok = all(w in got for w in want_present) and not any(w in got for w in want_absent)
        cases.append(ok)
        print(("ok  " if ok else "FAIL") + f"  {label}" + ("" if ok else f"\n      got {sorted(got)}"))

    # 1. The serial-3 draft: 2.3.0 accepts it (its own bundled copy, serial 3); TF refuses ({{path}} etc.).
    got, doc = kinds("app-2.3.0", by_name["app-2.3.0"]["_bundled_bytes"])
    case("2.3.0 accepts its own bundled bytes", got, want_absent=[("fail", "refuses-file", "")])
    got, _ = kinds("testflight-serial2", bump(s3, s3["serial"]), s2)
    case("TF serial-2 refuses serial 3 (unknown placeholder) where it accepted serial 2", got,
         [("fail", "refuses-file", "")])
    # 2. A later selector key: TF ignores it and would RUN the line; 2.3.0 defers to its bundled copy.
    later = bump(s3, s3["serial"] + 1)
    later["intents"]["tmux.install"].insert(0, {"families": ["apt"], "init": "openrc", "run": "{{sudo}}apk add tmux",
                                                "ci": {"skip": "x"}})
    later["intents"]["tmux.install"][0]["ids"] = ["debian"]
    got, _ = kinds("app-2.3.0", later, s3)
    case("2.3.0: a later key makes the variant unusable (no later-line)", got,
         want_absent=[("fail", "later-line", "tmux.install"), ("fail", "refuses-file", "")])
    tf_later = bump(s2, 3)
    tf_later["intents"]["tmux.install"].insert(0, {"families": ["apt"], "ids": ["debian"], "init": "openrc",
                                                   "run": "{{sudo}}apk add tmux"})
    got, _ = kinds("testflight-serial2", tf_later, s2)
    case("TF: a later key is ignored, the line would run (later-line)", got, [("fail", "later-line", "tmux.install")])
    # 3. minSchema 2: 2.3.0 honours it; TF ignores it.
    ms = bump(s2, 3)
    ms["intents"]["git.install"].insert(0, {"families": ["apt"], "ids": ["ubuntu"], "minSchema": 2,
                                            "run": "{{sudo}}apt-get install -y git-all"})
    got, _ = kinds("testflight-serial2", ms, s2)
    case("TF: minSchema 2 ignored (later-line)", got, [("fail", "later-line", "git.install")])
    ms3 = bump(s3, s3["serial"] + 1)
    ms3["intents"]["git.install"].insert(0, {"families": ["apt"], "ids": ["ubuntu"], "minSchema": 2,
                                             "run": "{{sudo}}apt-get install -y git-all"})
    got, _ = kinds("app-2.3.0", ms3, s3)
    case("2.3.0: minSchema 2 honoured", got, want_absent=[("fail", "later-line", "git.install")])
    # 4. A later placeholder: 2.3.0 keeps the file; TF refuses it.
    lp = bump(s3, s3["serial"] + 1)
    lp["intents"]["git.install"].insert(0, {"families": ["apt"], "ids": ["ubuntu"], "run": "{{sudo}}apt-get "
                                            "install -y {{flavour}}"})
    got, _ = kinds("app-2.3.0", lp, s3)
    case("2.3.0: later placeholder = unusable variant, file kept", got, want_absent=[("fail", "refuses-file", "")])
    # 5. Coverage: dropping a bundled intent refuses the file.
    drop = bump(s3, s3["serial"] + 1)
    del drop["intents"]["sshd.reload"]
    got, _ = kinds("app-2.3.0", drop, s3)
    case("2.3.0: dropping a bundled intent refuses the file", got, [("fail", "refuses-file", "")])
    # 6. Same serial, different bytes.
    same = copy.deepcopy(s3)
    same["date"] = "2026-12-31"
    got, _ = kinds("app-2.3.0", same)
    case("2.3.0: the bundled serial with other bytes is refused", got, [("fail", "refuses-file", "")])
    # 7. Older than bundled: info, not a failure.
    got, _ = kinds("app-2.3.0", s2)
    case("2.3.0: serial 2 is older than its bundled copy (info)", got, [("info", "older-than-bundled", "")],
         [("fail", "refuses-file", "")])
    # 8. A privileged agent line: dropped by the app.
    priv = bump(s3, s3["serial"] + 1)
    priv["intents"]["herdr.install"][0]["run"] = "{{sudo}}sh /tmp/x"
    got, _ = kinds("app-2.3.0", priv, s3)
    case("2.3.0: a {{sudo}} herdr line is dropped by the app (privileged)", got, [("fail", "privileged",
                                                                                   "herdr.install")])
    # 9. {{path}} where the app passes no path: the app falls back to its bundled line (info).
    dead = bump(s3, s3["serial"] + 1)
    dead["intents"]["git.install"][0]["run"] = "{{sudo}}apt-get install -y git && ls {{path}}"
    got, _ = kinds("app-2.3.0", dead, s3)
    case("2.3.0: an unsupplied {{path}} renders nil, bundled fallback (info)", got,
         [("info", "render-fallback", "git.install")], [("fail", "refuses-file", "")])
    # 10. A misplaced {{group}} refuses the file for 2.3.0.
    grp = bump(s3, s3["serial"] + 1)
    grp["intents"]["sudo.grant"][0]["run"] = "{{sudo}}usermod {{group}} -aG {{user}}"
    got, _ = kinds("app-2.3.0", grp, s3)
    case("2.3.0: a misplaced {{group}} refuses the file", got, [("fail", "refuses-file", "")])
    # 11. Explicit nulls in optional keys read as absent (decodeIfPresent), no crash.
    nulls = bump(s3, s3["serial"] + 1)
    nulls["intents"]["git.install"][0].update({"admin": None, "minSchema": None, "ids": None})
    got, _ = kinds("app-2.3.0", nulls, s3)
    case("2.3.0: null admin / minSchema / ids are absent, the file is kept", got,
         want_absent=[("fail", "refuses-file", "")])
    # 12. A trailing newline in a token is refused (Swift checks every character; `$` alone would allow it).
    nl = bump(s3, s3["serial"] + 1)
    nl["intents"]["git.install"][0]["families"] = ["apt\n"]
    got, _ = kinds("app-2.3.0", nl, s3)
    case("2.3.0: a family with a trailing newline refuses the file", got, [("fail", "refuses-file", "")])
    # 13. Exit status and the result file through run().
    with tempfile.TemporaryDirectory() as tmp:
        cand = os.path.join(tmp, "c.json")
        with open(cand, "wb") as handle:
            handle.write(dump(drop))
        failed, result = run(cand, None, profiles, distros, json_out=os.path.join(tmp, "r.json"), quiet=True)
        case("run(): a blocking failure exits non-zero and records a bug-labelled result", {
            ("failed", failed), ("label", any(r.get("label") == "bug" for r in result["results"]))},
            [("failed", True), ("label", True)])
        failed, result = run(cand, None, profiles, distros, path="recipes.json", quiet=True)
        case("run(--path recipes.json): only the TF profile, non-blocking", {
            ("failed", failed), ("covers", tuple(result["covers"]))},
            [("failed", False), ("covers", ("compat:testflight-serial2",))])
    # 13. meshTerm S5 app review M2: a packagesByIntent key is an fnmatch pattern (2.4's `security-updates.*`, the
    # Swift reader's prefix rule), with whole-word openers and no install word before {{packages}} but apt-get's own
    # upgrade-only form in security-updates.apt. An exact-key lookup never placement-checked these intents.
    su = copy.deepcopy(by_name["app-2.3.0"])
    su["profile"] = "app-2.4.0-sim"
    su["reader"]["placement"]["packagesByIntent"]["security-updates.*"] = ["--only-upgrade -y ", "upgrade -y ",
                                                                            "upgrade "]
    su["reader"]["placement"]["packagesWholeWord"] = ["security-updates.*"]
    su["reader"]["placement"]["packagesNoInstallWordBefore"] = {
        "security-updates.*": ["add", "install", "reinstall", "localinstall", "groupinstall"]}
    su["reader"]["placement"]["packagesInstallWordException"] = {"security-updates.apt": "install --only-upgrade -y "}
    sim = Reader(su)
    for run_, intent, ok in [
            ("{{sudo}}apt-get update && {{sudo}}apt-get install --only-upgrade -y {{packages}}", "security-updates.apt",
             True),
            ("{{sudo}}apk -U upgrade {{packages}}", "security-updates.apk", True),
            ("{{sudo}}dnf --refresh upgrade -y {{packages}}", "security-updates.dnf", True),
            ("echo {{packages}}", "security-updates.apt", False),
            ("{{sudo}}apt-get install -y {{packages}}", "security-updates.apt", False),
            ("{{sudo}}pip install --upgrade {{packages}}", "security-updates.apt", False),
            ("{{sudo}}foo-upgrade {{packages}}", "security-updates.apk", False),
            ("{{sudo}}apk add upgrade {{packages}}", "security-updates.apk", False),
            ("{{sudo}}dnf install --only-upgrade -y {{packages}}", "security-updates.dnf", False),
            ("{{sudo}}dnf reinstall upgrade -y {{packages}}", "security-updates.dnf", False),
            ("{{sudo}}dnf localinstall upgrade -y {{packages}}", "security-updates.dnf", False),
            ("{{sudo}}dnf groupinstall upgrade -y {{packages}}", "security-updates.dnf", False),
            ("{{sudo}}apt-get install -y {{packages}}", "sudo.install", True),
            ("{{sudo}}echo {{packages}}", "tmux.install", True)]:
        try:
            sim.parse_template(run_, intent)
            got_ok = True
        except Refused:
            got_ok = False
        case(f"2.4 placement ({'ok' if ok else 'refused'}): {intent}: {run_}", {got_ok}, [ok])
    bad_su = bump(s3, s3["serial"] + 1)
    bad_su["intents"]["security-updates.apt"] = [{"families": ["apt"], "run": "{{sudo}}apt-get install -y {{packages}}"}]
    su["intents"] = list(su.get("intents") or []) + ["security-updates.apt"]
    findings, _ = check_profile(su, dump(bad_su), dump(s3), distros)
    got = {(status, kind, intent) for status, kind, intent, _ in findings}
    case("2.4 sim: a security-updates.apt line installing {{packages}} refuses the file", got,
         [("fail", "refuses-file", "")])
    # 14. The real 2.4.0 profile (compat/app-2.4.0.json, meshTerm's RecipesCompat fixture): it accepts its own bundled
    # serial 12, and a line it refuses (an install verb before {{packages}} in security-updates.dnf) refuses the whole
    # file for 2.4.0 while 2.3.0, which has no security-updates.* placement rule, keeps it: the live check catches what
    # only the 2.4 app would refuse.
    s12 = json.loads(by_name["app-2.4.0"]["_bundled_bytes"])
    got, _ = kinds("app-2.4.0", by_name["app-2.4.0"]["_bundled_bytes"])
    case("2.4.0 accepts its own bundled bytes (serial 12)", got, want_absent=[("fail", "refuses-file", "")])
    refused = bump(s12, 13)
    refused["intents"]["security-updates.dnf"][0]["run"] = "{{sudo}}dnf install -y {{packages}}"
    got, _ = kinds("app-2.4.0", refused, s12)
    case("2.4.0: dnf install -y {{packages}} in security-updates.dnf refuses the file", got,
         [("fail", "refuses-file", "")])
    got, _ = kinds("app-2.3.0", refused, s12)
    case("2.3.0: the same line is not a placement refusal there (no security-updates.* rule)", got,
         want_absent=[("fail", "refuses-file", "")])
    with tempfile.TemporaryDirectory() as tmp:
        cand = os.path.join(tmp, "c.json")
        with open(cand, "wb") as handle:
            handle.write(dump(refused))
        failed, result = run(cand, None, profiles, distros, quiet=True)
        case("run(): the 2.4.0-only refusal is a blocking failure labelled bug under compat:app-2.4.0", {
            ("failed", failed), ("bug", any(r.get("label") == "bug" and r.get("check") == "compat:app-2.4.0"
                                            for r in result["results"]))},
            [("failed", True), ("bug", True)])
    # 15. Capitalised rpm names (2.4 S5): security-updates.dnf renders the host's rpm names (NetworkManager,
    # perl-DBI) under 2.4.0's capitalisedPackageIntents + rpmPackageName; every other intent keeps the lowercase rule,
    # and a reader without the rule renders nil for them (HostRecipeValues.value(for:rpmNames:)).
    r24 = Reader(by_name["app-2.4.0"])
    alma = next(d for d in distros if d.get("id") == "almalinux")
    text, _, origin = r24.command(r24.decode(by_name["app-2.4.0"]["_bundled_bytes"]),
                                  r24.decode(by_name["app-2.4.0"]["_bundled_bytes"]), "security-updates.dnf", alma)
    case("2.4.0: security-updates.dnf renders capitalised rpm names on AlmaLinux", {(origin, text)},
         [("file", "sudo dnf --refresh upgrade -y NetworkManager perl-DBI openssl-libs")])
    for intent, names, want in [
            ("security-updates.dnf", ["NetworkManager", "perl-DBI"], True),
            ("security-updates.dnf", ["kernel", "openssl-libs"], True),
            ("security-updates.dnf", ["-NetworkManager"], False),
            ("security-updates.dnf", ["Network Manager"], False),
            ("security-updates.dnf", ["N" * 65], False),
            ("security-updates.apt", ["NetworkManager"], False),
            ("security-updates.apk", ["NetworkManager"], False),
            ("packages.install", ["NetworkManager"], False),
            ("security-updates.apt", ["libc6"], True)]:
        case(f"2.4.0 {{{{packages}}}} for {intent}: {names[0][:20]} {'taken' if want else 'refused'}",
             {r24.packages_value(intent, names) is not None}, [want])
    no_rpm = copy.deepcopy(by_name["app-2.4.0"])
    no_rpm["reader"]["placement"].pop("capitalisedPackageIntents", None)
    text, _, origin = Reader(no_rpm).command(r24.decode(no_rpm["_bundled_bytes"]), r24.decode(no_rpm["_bundled_bytes"]),
                                             "security-updates.dnf", alma)
    case("2.4.0 without capitalisedPackageIntents: capitalised names render nil (no command)", {(origin, text)},
         [("none", None)])
    bad = len(cases) - sum(cases)
    print("self-test:", "PASS" if not bad else f"{bad} FAILED")
    return 1 if bad else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--candidate", default=os.path.join(ROOT, "recipes.json"))
    parser.add_argument("--previous", help="the file the apps have now (the deployed one): no regression against it")
    parser.add_argument("--profiles", default=os.path.join(ROOT, "compat"))
    parser.add_argument("--profile", action="append", help="only this profile (repeatable)")
    parser.add_argument("--path", help="only the profiles that fetch this published path")
    parser.add_argument("--source", default="main")
    parser.add_argument("--json", help="write a recipes-watch result file here")
    parser.add_argument("--summary", help="append a Markdown block here (GITHUB_STEP_SUMMARY)")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    profiles = load_profiles(args.profiles, args.profile)
    with open(os.path.join(args.profiles, "distros.json")) as handle:
        distros = json.load(handle)["distros"]
    failed, _ = run(args.candidate, args.previous, profiles, distros, path=args.path, source=args.source,
                    json_out=args.json, summary=args.summary)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
