#!/usr/bin/env python3
"""Run every recipe on fresh distro containers and check the result.

For each image in ci/images.json, each recipe family tested there and each intent, the harness picks the variant
the app would pick for that image (`recipes_lib.select`, from the image's /etc/os-release ID and VERSION_ID, and, for
the Containers intents only (`recipes_lib.ID_LIKE_INTENTS`), the parent its ID_LIKE inherits through the file's
top-level `idLike`, as meshTerm 2.3.2 resolves it),
renders it the way the app does, and runs it in a FRESH container (one at a time, `docker run --rm`):

  root   the bare form (no sudo), as root, on the untouched image (empty package lists and all).
  user   the sudo form, as a non-root user `mt` with passwordless sudo, on the image plus sudo (package lists
         emptied again after sudo is installed, so a recipe still has to refresh them itself).
  su     the app's `su -c '...'` form for a host with no sudo (the root password): the bare form, run through
         `su -c` from `mt`'s LOGIN shell, so it gets that user's PATH (on Debian no /usr/sbin or /sbin), as on a
         real host. Only variants with `ci.su` on images marked `suMode` in ci/images.json.

then runs the variant's `ci.check` as root (MT_USER names the user the recipe ran as). A variant's `ci` block says
what to skip (`skip`, `skipOn`, `rootOnly`, `userOnly`), what to install first as root (`needs`, ids from the
packages table; `before`, a shell line), the `{{packages}}` value (`packages`; packages.install uses every name for
the image's family) and which images are known to fail (`xfail`, reported, never red; an XPASS asks for the entry
to go).

    scripts/run-recipes.py                               # the whole matrix (slow: one container per case)
    scripts/run-recipes.py --image debian:12 --mode root # a slice
    scripts/run-recipes.py --intent tmux.install --intent git.install
    scripts/run-recipes.py --list                        # print what would run, without Docker
    scripts/run-recipes.py --summary "$GITHUB_STEP_SUMMARY"

Exit status 1 when any case FAILs (an unexpected failure, or a check that does not hold).
"""
import argparse
import json
import os
import shlex
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import recipes_lib as lib  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TIMEOUT = 20 * 60
# How much of a failing case's output (stdout and stderr, interleaved) the log and the summary show.
TAIL_LINES = 30
# The image's own package-manager family (for `needs` and the sudo set-up), from os-release ID / ID_LIKE.
NATIVE = {"debian": "apt", "ubuntu": "apt", "fedora": "dnf", "rocky": "dnf", "rockylinux": "dnf", "rhel": "dnf", "almalinux": "dnf",
          "centos": "dnf", "alpine": "apk", "amzn": "dnf", "amazonlinux": "dnf", "arch": "pacman", "archlinux": "pacman",
          "manjaro": "pacman", "cachyos": "pacman",
          "opensuse-leap": "zypper", "opensuse": "zypper", "leap": "zypper", "opensuse-tumbleweed": "zypper"}
SUDO_SETUP = {
    "apt": "apt-get update -qq && apt-get install -y -qq sudo >/dev/null && rm -rf /var/lib/apt/lists/* "
           "&& useradd -m -s /bin/sh mt",
    # Fedora's container image has neither sudo nor su (util-linux).
    "dnf": "{ { command -v sudo && command -v su; } >/dev/null || dnf install -y -q sudo util-linux >/dev/null; } "
           "&& useradd -m -s /bin/sh mt",
    "apk": "apk add -q sudo && adduser -D -s /bin/sh mt",
    # Arch's image has no sync database: sudo needs one, then it is removed again so a recipe still has to sync.
    "pacman": "pacman -Sy --noconfirm --needed sudo >/dev/null && rm -f /var/lib/pacman/sync/*.db "
              "&& useradd -m -s /bin/sh mt",
    "zypper": "{ command -v sudo >/dev/null || zypper -n -q install sudo >/dev/null; } && useradd -m -s /bin/sh mt",
}


def parse_os_release(text):
    """os-release's fields as a shell that sources it reads them (the app's probe does `. /etc/os-release`): each
    value is one shell word, so single and double quotes and backslash escapes are removed (shlex). A line shlex
    cannot read (an unclosed quote) or that is not KEY=value is skipped. Returns (ID, VERSION_ID, ID_LIKE tokens)."""
    fields = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        try:
            words = shlex.split(value, comments=True)
        except ValueError:
            continue
        fields[key.strip()] = " ".join(words)
    return (fields.get("ID", "").lower(), fields.get("VERSION_ID") or None,
            fields.get("ID_LIKE", "").lower().split())


def os_release(image):
    out = subprocess.run(["docker", "run", "--rm", image, "cat", "/etc/os-release"], check=True,
                         capture_output=True, text=True, timeout=600).stdout
    return parse_os_release(out)


def packages_for(doc, variant, intent, native):
    ci = variant.get("ci", {})
    if "packages" in ci:
        return ci["packages"]
    if intent == "packages.install":
        names = []
        for entry in doc["packages"].values():
            name = entry.get(native)
            if name and name not in names:
                names.append(name)
        return names
    return None


def needs_line(doc, ci, native):
    names = [doc["packages"][pid].get(native) for pid in ci.get("needs", [])]
    names = [n for n in names if n]
    if not names:
        return ""
    variant = lib.select(doc, "packages.install", native)
    return lib.render(variant["run"], sudo=False, packages=names) if variant else ""


def plan(doc, matrix, args):
    """Yield (image, mode, family, intent, variant, command, packages) cases, and the skips."""
    for entry in matrix["images"]:
        image = entry["image"]
        if args.image and image not in args.image:
            continue
        distro_id, version_id, id_like = entry.get("id"), entry.get("versionID"), entry.get("idLike", [])
        if distro_id is None and not args.list:
            try:
                distro_id, version_id, id_like = os_release(image)
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
                print(f"FAIL  {image}: cannot read /etc/os-release ({error})", flush=True)
                yield dict(image=image, mode="-", family="-", intent="(image)", variant={"ci": {}}, native="",
                           command=None, skip=None)
                continue
        distro_id = distro_id or image.split(":")[0].split("/")[-1]
        # A derivative the table does not list: its first ID_LIKE token the table knows (Garuda -> arch -> pacman).
        native = NATIVE.get(distro_id) or next((NATIVE[t] for t in id_like if t in NATIVE), "")
        for family in entry["families"]:
            for intent in sorted(doc["intents"]):
                if args.intent and intent not in args.intent:
                    continue
                # Only the intents meshTerm asks with the ID_LIKE parent (lib.ID_LIKE_INTENTS) get it.
                parent = lib.intent_parent(doc, intent, distro_id, id_like, lib.CONTAINERS_CLASSIFIER_IDS)
                variant = lib.select(doc, intent, family, distro_id, version_id, parent_id=parent)
                if variant is None:
                    continue
                if family == "any" or "any" in variant["families"]:
                    if family != "any":
                        continue  # an `any` line is tested once per image, in the `any` pass
                elif family not in variant["families"]:
                    continue
                ci = variant.get("ci", {})
                modes = ("root", "user") + (("su",) if entry.get("suMode") and ci.get("su") else ())
                for mode in modes:
                    if args.mode and mode != args.mode:
                        continue
                    why = None
                    if "skip" in ci:
                        why = ci["skip"]
                    elif image in ci.get("skipOn", {}):
                        why = ci["skipOn"][image]
                    elif mode == "user" and "rootOnly" in ci:
                        why = ci["rootOnly"]
                    elif mode == "root" and "userOnly" in ci:
                        why = ci["userOnly"]
                    packages = packages_for(doc, variant, intent, native)
                    # `{{user}}` is the case's own user, as the app renders a known SSH user (not `$USER`, which a
                    # root `docker run` does not set); `ci.user` names another (root setting sudo up FOR a user).
                    user = ci.get("user") or ("root" if mode == "root" else "mt")
                    command = lib.render(variant["run"], sudo=(mode == "user"), user=user,
                                         packages=packages, port=ci.get("port"), proto=ci.get("proto"),
                                         group=ci.get("group"), path=ci.get("path"))
                    yield dict(image=image, mode=mode, family=family, intent=intent, variant=variant, native=native,
                               command=command, skip=why)


def run_case(doc, case):
    ci = case["variant"]["ci"]
    lines = ["set -e", "export DEBIAN_FRONTEND=noninteractive"]
    if case["mode"] == "su":
        # No sudoers entry: root's password (emptied here, so su asks for nothing) is the way to root.
        lines += [SUDO_SETUP[case["native"]], "passwd -d root >/dev/null"]
    if case["mode"] == "user":
        lines += [SUDO_SETUP[case["native"]],
                  "echo 'mt ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/mt",
                  "echo 'Defaults env_keep += \"DEBIAN_FRONTEND\"' >> /etc/sudoers.d/mt",
                  "chmod 0440 /etc/sudoers.d/mt"]
    prep = needs_line(doc, ci, case["native"])
    if prep:
        # Best effort: the harness's own set-up (an image may already have the tool another way, as Rocky's
        # curl-minimal); the recipe and its check decide the result.
        lines.append("{ " + prep + "; } >/dev/null 2>&1 || true")
    if ci.get("before"):
        lines.append(ci["before"] + " >/dev/null")
    user = "root" if case["mode"] == "root" else "mt"
    lines.append(f"export MT_USER={user}")
    lines.append("echo '--- recipe'")
    if case["mode"] == "su":
        # `su - mt`: the user's login shell (its PATH from /etc/profile); then the app's `su -c`, which keeps it.
        lines.append("set +e; su - mt -s /bin/sh -c 'su -c \"sh /t/recipe.sh\"' </dev/null; rc=$?; set -e")
    elif case["mode"] == "user":
        lines.append("set +e; su mt -s /bin/sh -c 'cd && sh /t/recipe.sh' </dev/null; rc=$?; set -e")
    else:
        lines.append("set +e; (cd /root && sh /t/recipe.sh) </dev/null; rc=$?; set -e")
    lines.append('[ "$rc" = 0 ] || { echo "--- recipe exit $rc"; exit 10; }')
    lines.append("echo '--- check'")
    lines.append(f"sh -c {shlex.quote(ci['check'])} >/dev/null || {{ echo '--- check failed'; exit 11; }}")
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "recipe.sh"), "w") as handle:
            handle.write(case["command"] + "\n")
        with open(os.path.join(tmp, "case.sh"), "w") as handle:
            handle.write("\n".join(lines) + "\n")
        os.chmod(tmp, 0o755)
        for name in ("recipe.sh", "case.sh"):
            os.chmod(os.path.join(tmp, name), 0o644)
        started = time.time()
        try:
            # stderr into stdout, so the tail reads in the order it was written (the error beside its step).
            result = subprocess.run(["docker", "run", "--rm", "-v", f"{tmp}:/t:ro", case["image"], "sh", "/t/case.sh"],
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=TIMEOUT)
            code, output = result.returncode, result.stdout.decode("utf-8", "replace")
        except subprocess.TimeoutExpired as error:
            partial = error.stdout or b""
            code, output = 124, (partial.decode("utf-8", "replace") if isinstance(partial, bytes) else partial) + "\ntimed out"
        return code, output, time.time() - started


def tail(output, lines=TAIL_LINES):
    """The last `lines` lines of a case's output, indented under its result line (empty lines dropped)."""
    kept = [line.rstrip() for line in output.splitlines() if line.strip()][-lines:]
    return "\n".join("      | " + line for line in kept) if kept else "      | (no output)"


def self_test():
    """parse_os_release against what `. /etc/os-release` gives a shell."""
    failures = 0
    for text, want in [
            ('ID=arch\nVERSION_ID=1\n', ("arch", "1", [])),
            ('ID="rocky"\nID_LIKE="rhel centos fedora"\nVERSION_ID="9.8"\n', ("rocky", "9.8", ["rhel", "centos", "fedora"])),
            ("ID='elementary'\nID_LIKE='ubuntu debian'\n", ("elementary", None, ["ubuntu", "debian"])),
            ('ID=Kali\nID_LIKE=debian # comment\n', ("kali", None, ["debian"])),
            ('# a comment\n\nID=x\nID_LIKE="a \\"b\\""\nVERSION_ID=\n', ("x", None, ["a", '"b"'])),
            ('ID="unclosed\nID_LIKE=arch\n', ("", None, ["arch"])),
            ('  ID=mageia\nID_LIKE="mandriva fedora"\n', ("mageia", None, ["mandriva", "fedora"]))]:
        got = parse_os_release(text)
        if got != want:
            print(f"self-test FAIL: parse_os_release({text!r}): {got!r}, expected {want!r}")
            failures += 1
    print("self-test:", "OK" if not failures else f"{failures} FAILED")
    return 1 if failures else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--image", action="append")
    parser.add_argument("--intent", action="append")
    parser.add_argument("--mode", choices=("root", "user", "su"))
    parser.add_argument("--list", action="store_true", help="print the cases, run nothing")
    parser.add_argument("--summary", help="append a Markdown table here (GITHUB_STEP_SUMMARY)")
    parser.add_argument("--self-test", action="store_true", help="test the os-release parser and exit")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    with open(os.path.join(ROOT, "recipes.json"), "rb") as handle:
        doc = lib.load(handle.read())
    with open(os.path.join(ROOT, "ci", "images.json")) as handle:
        matrix = json.load(handle)

    rows, failed, failures = [], 0, []
    for case in plan(doc, matrix, args):
        label = f"{case['image']:<14} {case['mode']:<4} {case['family']:<7} {case['intent']}"
        if case["skip"]:
            rows.append((case, "SKIP", case["skip"]))
            print(f"SKIP  {label}: {case['skip']}")
            continue
        if case["command"] is None:
            rows.append((case, "FAIL", "the recipe does not render (placeholders)"))
            print(f"FAIL  {label}: does not render")
            failed += 1
            continue
        if args.list:
            print(f"RUN   {label}\n      {case['command']}")
            continue
        code, output, seconds = run_case(doc, case)
        xfail = case["variant"]["ci"].get("xfail", {}).get(case["image"])
        if code == 0:
            status, note = ("XPASS", f"passes now: remove its xfail ({xfail})") if xfail else ("PASS", "")
        else:
            why = {10: "the recipe failed", 11: "the check failed: " + case["variant"]["ci"]["check"],
                   124: "timed out"}.get(code, f"exit {code}")
            status, note = ("XFAIL", xfail) if xfail else ("FAIL", why)
            if status == "FAIL":
                failed += 1
        rows.append((case, status, note))
        print(f"{status:<5} {label} ({seconds:.0f} s){': ' + note if note else ''}", flush=True)
        if status == "FAIL":
            # The diagnosis: what the recipe (or its check) printed last, right under the FAIL line.
            print(f"      last {TAIL_LINES} lines of output:\n{tail(output)}", flush=True)
            failures.append((label, note, tail(output)))
            if os.environ.get("GITHUB_ACTIONS") == "true":
                print(f"::error title=recipe FAIL::{label.split()[0]} {case['mode']} {case['intent']}: {note}")

    if args.summary and not args.list:
        with open(args.summary, "a") as handle:
            handle.write("| Image | Mode | Family | Intent | Result | Note |\n|---|---|---|---|---|---|\n")
            for case, status, note in rows:
                handle.write(f"| {case['image']} | {case['mode']} | {case['family']} | `{case['intent']}` | "
                             f"{status} | {str(note).replace('|', '/')} |\n")
            for label, note, text in failures:
                handle.write(f"\n<details><summary>FAIL {label}: {note}</summary>\n\n```\n{text}\n```\n</details>\n")
    counts = {s: sum(1 for _, st, _ in rows if st == s) for s in ("PASS", "FAIL", "XFAIL", "XPASS", "SKIP")}
    print("summary: " + ", ".join(f"{k} {v}" for k, v in counts.items()))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
