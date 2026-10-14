"""The host-recipes rules, shared by the validator, the distro test harness and the signing helper.

These are the SAME rules meshTerm applies before it uses a file (MeshTermFailures, HostRecipeDocument.swift and
HostRecipeTemplate.swift). Change one side, change the other: a file this validator passes must be one every
supported app accepts, or the apps quietly keep their old copy.
"""
import json
import re

KIND = "host-recipes"
SCHEMA = 1
MAX_BYTES = 256 * 1024
MAX_RUN = 2000
PLACEHOLDERS = {"sudo", "user", "packages", "port", "proto", "group", "path"}
# A placeholder name a LATER app may know: a variant using one is unusable here (the app falls back to its bundled
# copy for that intent and OS), never a refused file. Anything else between {{ }} refuses the file.
FUTURE_PLACEHOLDER = re.compile(r"^[a-z][a-z0-9-]{0,31}\Z")
# The variant keys this format knows. A variant with another key (a later selector) is unusable here.
VARIANT_KEYS = {"families", "ids", "versions", "run", "admin", "ci", "minSchema"}
# `{{group}}` (the admin group, `sudo` or `wheel`): only as usermod's group or addgroup's second word.
GROUP_OPENERS = ("-aG ", "-G ", "addgroup {{user}} ")
# `{{packages}}` in sudo.install: only right after an install verb, or as a shell variable's value.
SUDO_INSTALL_PACKAGE_OPENERS = ("install -y ", "add ", "-S --noconfirm ", 'p="')
PROTOS = ("tcp", "udp")
GROUPS = ("sudo", "wheel")
PATH_VALUE = re.compile(r"^/[A-Za-z0-9._/+-]{1,255}\Z")
# The families the app knows. A variant may name others (ignored by today's apps); see README.
# `windows` (a Windows OpenSSH host, meshTerm 2.3.0): its lines are PowerShell 5.1, and an `any` line (POSIX) never
# applies to it (`score`).
FAMILIES = {"apt", "dnf", "yum", "apk", "pacman", "zypper", "macos", "unknown", "any", "windows"}

TOKEN = re.compile(r"^[a-z0-9-]{1,32}\Z")
IDENTIFIER = re.compile(r"^[A-Za-z0-9]{1,32}\Z")
DISTRO_ID = re.compile(r"^[a-z0-9._-]{1,64}\Z")
PACKAGE = re.compile(r"^[a-z0-9][a-z0-9.+_-]{0,63}\Z")
INTENT = re.compile(r"^[a-z0-9]+(?:[.-][a-z0-9]+)*\Z")
DATE = re.compile(r"^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])\Z")
VERSION = re.compile(r"^[0-9]{1,9}(\.[0-9]{1,9}){0,5}\Z")
SUDO_OPENERS = ("&& ", "; ", "then ", "| ")


class RecipeError(Exception):
    pass


def _pairs(items):
    keys = [key for key, _ in items]
    if len(set(keys)) != len(keys):
        raise RecipeError(f"duplicate key in one object: {sorted(k for k in keys if keys.count(k) > 1)[0]}")
    return dict(items)


def is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def parse_version(text):
    return [int(part) for part in text.split(".")] if isinstance(text, str) and VERSION.match(text) else None


def compare_versions(a, b):
    for i in range(max(len(a), len(b))):
        x = a[i] if i < len(a) else 0
        y = b[i] if i < len(b) else 0
        if x != y:
            return -1 if x < y else 1
    return 0


def _word_at(text, i, word, word_chars):
    before = text[i - 1] if i > 0 else None
    after = text[i + len(word)] if i + len(word) < len(text) else None
    return (before is None or before not in word_chars) and (after is None or after not in word_chars)


# Commands that change privilege. Matched as whole words; `/` and quotes are boundaries, so `/usr/bin/sudo` and
# `"su"` count, while `sudoers.d`, `--user` and `pseudo` do not.
PRIVILEGE_WORDS = ("sudo", "su", "doas", "pkexec", "run0")
WORD_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.")
USER_ENDS = set(" ;&|)")


def contains_word(text, word):
    start = text.find(word)
    while start >= 0:
        before = text[start - 1] if start > 0 else None
        after = text[start + len(word)] if start + len(word) < len(text) else None
        if (before is None or before not in WORD_CHARS) and (after is None or after not in WORD_CHARS):
            return True
        start = text.find(word, start + 1)
    return False


def check_user_placement(run):
    """`{{user}}` only as a standalone word outside quotes (the app substitutes one already-quoted word)."""
    quote = None
    i = 0
    while i < len(run):
        if run.startswith("{{user}}", i):
            before = run[i - 1] if i > 0 else None
            after = run[i + 8] if i + 8 < len(run) else None
            if quote is not None or (before is not None and before != " ") or (after is not None and after not in USER_ENDS):
                raise RecipeError("{{user}} must be a word of its own, outside quotes")
            i += 8
            continue
        c = run[i]
        if quote is None and c in "'\"":
            quote = c
        elif quote is not None and c == quote:
            quote = None
        i += 1


def parse_template(run, intent=None):
    """Raise RecipeError unless `run` is a valid command template. Returns (the known placeholder names used, the
    unknown but well-formed ones). An unknown name makes the variant UNUSABLE here (a later app's placeholder); every
    other rule refuses the file, also in a variant that is unusable."""
    if not isinstance(run, str) or not run or len(run) > MAX_RUN:
        raise RecipeError("empty or too long")
    if any(not (0x20 <= ord(c) <= 0x7E) for c in run):
        raise RecipeError("not printable ASCII on one line")
    names, unknown, plain, rest, offset = [], [], "", run, 0
    while "{{" in rest:
        start = rest.index("{{")
        plain += rest[:start]
        end = rest.find("}}", start + 2)
        if end < 0:
            raise RecipeError("unclosed {{")
        name = rest[start + 2:end]
        before = run[:offset + start]
        if name not in PLACEHOLDERS:
            if not FUTURE_PLACEHOLDER.match(name):
                raise RecipeError(f"unknown placeholder {{{{{name}}}}}")
            unknown.append(name)
        elif name == "sudo":
            if before and not before.endswith(SUDO_OPENERS):
                raise RecipeError("{{sudo}} must open a command")
            after = rest[end + 2:]
            if not after or after[0] == " ":
                raise RecipeError("{{sudo}} needs a command after it")
        elif name == "group":
            if not before.endswith(GROUP_OPENERS):
                raise RecipeError("{{group}} only right after -aG , -G  or addgroup {{user}} ")
        elif name == "packages" and intent == "sudo.install":
            if not before.endswith(SUDO_INSTALL_PACKAGE_OPENERS):
                raise RecipeError("{{packages}} in sudo.install only right after an install verb or as p=\"...\"")
        if name in PLACEHOLDERS:
            names.append(name)
        plain += " "
        offset += end + 2
        rest = rest[end + 2:]
    plain += rest
    if "}}" in plain:
        raise RecipeError("stray }}")
    if names.count("packages") > 1:
        raise RecipeError("{{packages}} twice")
    for word in PRIVILEGE_WORDS:
        if contains_word(plain, word):
            raise RecipeError(f"a literal {word} (privilege is the app's: use {{{{sudo}}}})")
    for i, c in enumerate(run):
        if c == "\\" and ((i > 0 and run[i - 1].isalpha()) or (i + 1 < len(run) and run[i + 1].isalpha())):
            raise RecipeError("a backslash next to a letter (an escaped command word)")
    check_user_placement(run)
    return names, unknown


def check_template(run, intent=None):
    """Raise RecipeError unless `run` is a valid template every rule of this format accepts, with known placeholders
    only. Returns the placeholder names used."""
    names, unknown = parse_template(run, intent)
    if unknown:
        raise RecipeError(f"unknown placeholder {{{{{unknown[0]}}}}}")
    return names


def is_path_value(path):
    return isinstance(path, str) and bool(PATH_VALUE.match(path)) and "//" not in path and "/." not in path


def user_word(user):
    """The SSH user as one shell word (plain, or POSIX single-quoted); None when no quoting makes it safe."""
    if not user or user[0] == "-" or len(user) > 64 or any(ord(c) < 0x20 or ord(c) == 0x7F for c in user):
        return None
    return user if re.match(r"^[A-Za-z0-9._-]+$", user) else "'" + user.replace("'", "'\\''") + "'"


def render(run, sudo, user=None, packages=None, port=None, proto=None, group=None, path=None):
    """The app's rendering (HostRecipeTemplate.render): ONE pass over the template, so a value is never read as a
    placeholder. None when a used placeholder has no value, or a refused one (`{{user}}` alone defaults to $USER)."""
    values = {"sudo": "sudo " if sudo else ""}
    if user is None:
        values["user"] = "$USER"
    elif user_word(user) is not None:
        values["user"] = user_word(user)
    if packages and all(isinstance(p, str) and PACKAGE.match(p) for p in packages):
        values["packages"] = " ".join(packages)
    if is_int(port) and 1 <= port <= 65535:
        values["port"] = str(port)
    if proto in PROTOS:
        values["proto"] = proto
    if group in GROUPS:
        values["group"] = group
    if is_path_value(path):
        values["path"] = path
    out, rest = "", run
    while "{{" in rest:
        start = rest.index("{{")
        end = rest.index("}}", start + 2)
        name = rest[start + 2:end]
        if name not in values:
            return None
        out += rest[:start] + values[name]
        rest = rest[end + 2:]
    return out + rest


UNUSABLE = "_unusable"


def is_usable(doc, intent, index):
    return (intent, index) not in doc.get(UNUSABLE, ())


def unusable_variants(doc):
    """(intent, index) of every variant this format version cannot use (a later key, placeholder or minSchema)."""
    return sorted(doc.get(UNUSABLE, ()))


def load(data):
    """Parse and validate a recipes file (bytes). Returns the document dict. Raises RecipeError."""
    if len(data) > MAX_BYTES:
        raise RecipeError(f"larger than {MAX_BYTES} bytes")
    try:
        doc = json.loads(data.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, ValueError) as error:
        raise RecipeError(f"not JSON: {error}") from None
    if not isinstance(doc, dict):
        raise RecipeError("not a JSON object")
    if doc.get("kind") != KIND:
        raise RecipeError(f"kind is {doc.get('kind')!r}, not {KIND!r}")
    if doc.get("schema") != SCHEMA or not is_int(doc.get("schema")):
        raise RecipeError(f"schema {doc.get('schema')!r}: this validator (and the apps) read schema {SCHEMA}")
    if not is_int(doc.get("serial")) or doc["serial"] < 1:
        raise RecipeError("serial must be an integer >= 1")
    if not isinstance(doc.get("date"), str) or not DATE.match(doc["date"]):
        raise RecipeError("date must be YYYY-MM-DD")
    packages = doc.get("packages")
    if not isinstance(packages, dict):
        raise RecipeError("packages must be an object")
    for pid, names in packages.items():
        if not IDENTIFIER.match(pid) or not isinstance(names, dict):
            raise RecipeError(f"package {pid!r}")
        for family, name in names.items():
            if not TOKEN.match(family) or not isinstance(name, str) or not PACKAGE.match(name):
                raise RecipeError(f"package {pid} on {family!r}: {name!r}")
    intents = doc.get("intents")
    unusable = set()
    if not isinstance(intents, dict) or not intents:
        raise RecipeError("intents must be a non-empty object")
    for intent, variants in intents.items():
        if not INTENT.match(intent) or len(intent) > 64:
            raise RecipeError(f"intent id {intent!r}")
        if not isinstance(variants, list) or not variants:
            raise RecipeError(f"{intent}: a non-empty list of variants")
        selectors = set()
        for index, variant in enumerate(variants):
            where = f"{intent}[{index}]"
            if not isinstance(variant, dict):
                raise RecipeError(f"{where}: not an object")
            usable = not (set(variant) - VARIANT_KEYS)
            families = variant.get("families")
            if not isinstance(families, list) or not families or len(set(families)) != len(families) \
                    or not all(isinstance(f, str) and TOKEN.match(f) for f in families):
                raise RecipeError(f"{where}.families")
            ids = variant.get("ids")
            if "ids" in variant and (not isinstance(ids, list) or not ids or len(set(ids)) != len(ids)
                                     or not all(isinstance(i, str) and DISTRO_ID.match(i) for i in ids)):
                raise RecipeError(f"{where}.ids")
            low = high = None
            if "versions" in variant:
                versions = variant["versions"]
                if not isinstance(versions, dict) or not versions or set(versions) - {"min", "below"}:
                    raise RecipeError(f"{where}.versions")
                low, high = versions.get("min"), versions.get("below")
                if ("min" in versions and parse_version(low) is None) or \
                        ("below" in versions and parse_version(high) is None):
                    raise RecipeError(f"{where}.versions: dotted numbers only")
                if low and high and compare_versions(parse_version(low), parse_version(high)) >= 0:
                    raise RecipeError(f"{where}.versions is empty")
            try:
                _, unknown = parse_template(variant.get("run"), intent)
            except RecipeError as error:
                raise RecipeError(f"{where}.run: {error}") from None
            if unknown:
                usable = False
            if "admin" in variant and not isinstance(variant["admin"], bool):
                raise RecipeError(f"{where}.admin must be true or false")
            if "ci" in variant and not isinstance(variant["ci"], dict):
                raise RecipeError(f"{where}.ci must be an object")
            if "minSchema" in variant:
                if not is_int(variant["minSchema"]) or variant["minSchema"] < 1:
                    raise RecipeError(f"{where}.minSchema must be an integer >= 1")
                if variant["minSchema"] > SCHEMA:
                    usable = False
            selector = (tuple(sorted(families)), tuple(sorted(ids or [])), low or "", high or "")
            if selector in selectors:
                raise RecipeError(f"{where} repeats a selector")
            selectors.add(selector)
            if not usable:
                unusable.add((intent, index))
    doc[UNUSABLE] = unusable
    return doc


def is_family_fallback(variant):
    return "ids" not in variant and "versions" not in variant


def check_covers(doc, previous):
    """The app's coverage rule against an earlier file: no intent, family fallback or package dropped."""
    for intent, variants in previous["intents"].items():
        mine = doc["intents"].get(intent)
        if mine is None:
            raise RecipeError(f"drops intent {intent}")
        needed = {f for v in variants if is_family_fallback(v) for f in v["families"]}
        have = {f for v in mine if is_family_fallback(v) for f in v["families"]}
        if needed - have:
            raise RecipeError(f"drops {intent} on {sorted(needed - have)[0]}")
    for package in previous["packages"]:
        if package not in doc["packages"]:
            raise RecipeError(f"drops package {package}")


def score(variant, family, distro_id=None, version=None):
    """How specifically `variant` applies (higher wins), None when it does not (HostRecipeVariant.score)."""
    exact = family in variant["families"]
    if not exact and ("any" not in variant["families"] or family == "windows"):
        return None
    value = 1 if exact else 0
    if "ids" in variant:
        if not distro_id or distro_id.lower() not in variant["ids"]:
            return None
        value += 4
    if "versions" in variant:
        if version is None:
            return None
        low, high = variant["versions"].get("min"), variant["versions"].get("below")
        if low and compare_versions(version, parse_version(low)) < 0:
            return None
        if high and compare_versions(version, parse_version(high)) >= 0:
            return None
        value += 2
    return value


def select(doc, intent, family, distro_id=None, version_id=None, bundled=None):
    """The app's choice (HostRecipeDocument.variant): the most specific matching variant, file order on a tie. When an
    UNUSABLE variant (a later app's) applies at least as specifically as the best usable one, the answer for this
    intent and OS is the bundled document's (`bundled`; None without one), never a wider usable line."""
    best, best_score, blocked = None, None, None
    version = parse_version(version_id) if version_id else None
    for index, variant in enumerate(doc["intents"].get(intent, [])):
        value = score(variant, family, distro_id, version)
        if value is None:
            continue
        if not is_usable(doc, intent, index):
            blocked = value if blocked is None else max(blocked, value)
            continue
        if best_score is None or value > best_score:
            best, best_score = variant, value
    if blocked is not None and (best_score is None or blocked >= best_score):
        return select(bundled, intent, family, distro_id, version_id) if bundled is not None else None
    return best
