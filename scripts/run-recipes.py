#!/usr/bin/env python3
"""Run every recipe on fresh distro containers and check the result.

For each image in ci/images.json, each recipe family tested there and each intent, the harness picks the variant
the app would pick for that image (`recipes_lib.select`, from the image's /etc/os-release ID and VERSION_ID, and, for
the Containers intents only (`recipes_lib.ID_LIKE_INTENTS`), the parent its ID_LIKE inherits through the file's
top-level `idLike` and, on an `unknown` pass, the parent's family, as meshTerm 2.3.2 resolves them: `recipe_os`),
renders it the way the app does, and runs it in a FRESH container (one at a time, `docker run --rm`):

  root   the bare form (no sudo), as root, on the untouched image (empty package lists and all).
  user   the sudo form, as a non-root user `mt` with passwordless sudo, on the image plus sudo (package lists
         emptied again after sudo is installed, so a recipe still has to refresh them itself).
  su     the app's `su -c '...'` form for a host with no sudo (the root password): the bare form, run through
         `su -c` from `mt`'s LOGIN shell, so it gets that user's PATH (on Debian no /usr/sbin or /sbin), as on a
         real host, behind the root PATH line every app `su -c` form starts with (meshTerm SuRoot.command;
         SU_PATH_LINE here, not repeated for a line that already starts with it), so a bare `dpkg --configure -a`
         finds ldconfig as it does in the app. Only variants with `ci.su` on images marked `suMode` in ci/images.json.

then runs the variant's `ci.check` as root (MT_USER names the user the recipe ran as). A variant's `ci` block says
what to skip (`skip`, `skipOn`, `rootOnly`, `userOnly`), what to install first as root (`needs`, ids from the
packages table; `before`, a shell line), the `{{packages}}` value (`packages`; packages.install uses every name for
the image's family) and which images are known to fail (`xfail`, reported, never red; an XPASS asks for the entry
to go). An xfail may carry the message it was measured with (ci/xfail-expect.json, intent -> image -> regular
expression): then it passes only when the failing case's output matches it, and any other failure there is a FAIL.

    scripts/run-recipes.py                               # the whole matrix (slow: one container per case)
    scripts/run-recipes.py --image debian:12 --mode root # a slice
    scripts/run-recipes.py --intent tmux.install --intent git.install
    scripts/run-recipes.py --list                        # print what would run, without Docker
    scripts/run-recipes.py --summary "$GITHUB_STEP_SUMMARY"
    scripts/run-recipes.py --systemd-pid1 --image ubuntu:24.04   # the detached.* lines on the systemd path

`--systemd-pid1` (meshTerm docs/plan-2.5-navigation.md S9.8, serial 13): the fresh-distro containers above have no
init, so a `detached.*` line there always takes its setsid path. This mode builds each SYSTEMD_IMAGES image with
systemd and sudo, starts it with systemd as PID 1 (`/sbin/init`, `--cgroupns=host`, tmpfs `/run` and `/run/lock`,
the cgroup v2 hierarchy mounted read-write), runs every `detached.*` variant for the image's family rendered as the
app renders it (root and the sudo user, a fresh container per case), and asserts that the transient unit
`meshterm-<kind>-<id>` ran and ended cleanly (systemd logged it "Deactivated successfully", so the systemd path was
taken and not setsid), then the variant's own `ci.check` (the claimed state holds `pid=<digits>` and `rc=0`,
`ended=` is set, `/run/meshterm-pkg.lock` is gone, the log holds the package tool's output).

It runs the `security-updates.*` lines for the image's family the same way (serial 13: they start the package tool
with `systemd-run --wait --pipe` when systemd runs): there the transient unit is systemd-run's own `run-u<N>.service`,
which must have ended "Deactivated successfully" before the variant's `ci.check` runs.

Exit status 1 when any case FAILs (an unexpected failure, or a check that does not hold).
"""
import argparse
import json
import os
import re
import secrets
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
# meshTerm SuRoot.pathLine: the app's every `su -c` form starts with it (not twice when the line already does).
SU_PATH_LINE = 'PATH="$PATH:/usr/sbin:/sbin"; '
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
# An Arch DERIVATIVE's image (Manjaro, CachyOS) can lag its own repositories further than archlinux:latest: a partial
# upgrade (`-Sy sudo`) may pull a sudo built against newer libraries than the image has, so a derivative upgrades
# fully (-Syu) before sudo (meshTerm docs/container-idlike-alpine-plan.md 9.2, review 13). archlinux:latest keeps -Sy.
SUDO_SETUP_DERIVATIVE = {
    "pacman": "pacman -Syu --noconfirm --needed sudo >/dev/null && rm -f /var/lib/pacman/sync/*.db "
              "&& useradd -m -s /bin/sh mt",
}
# An Arch-family image is brought fully up to date before anything else in a case runs, then its sync databases are
# removed again (so a recipe still has to sync). Arch supports no partial upgrade: once the repositories move past the
# image (openssl 3 -> 4, 2026-11-10), the harness's own `pacman -Sy <pkg>` lines (the sudo set-up, a ci.before such as
# sshd.host-keys' openssh) fail "could not satisfy dependencies" before the recipe runs. A harness fix, not a recipe
# one: recipes.json (and so the signed, bundled bytes) is unchanged.
IMAGE_REFRESH = {
    "pacman": "pacman -Syu --noconfirm >/dev/null && rm -f /var/lib/pacman/sync/*.db",
}
# The distro ids whose image is the family's own (SUDO_SETUP); any other id with that native family is a derivative.
FAMILY_OWN_IDS = {"pacman": {"arch", "archlinux"}}


def load_xfail_expect(doc, path=None):
    """ci/xfail-expect.json's `expect` (intent -> image -> compiled pattern). Raises ValueError for an entry no
    variant's `ci.xfail` backs (a typo would otherwise never be consulted) or a pattern that does not compile."""
    path = path or os.path.join(ROOT, "ci", "xfail-expect.json")
    if not os.path.exists(path):
        return {}
    with open(path) as handle:
        expect = json.load(handle).get("expect", {})
    compiled = {}
    for intent, images in expect.items():
        variants = doc["intents"].get(intent)
        if variants is None:
            raise ValueError(f"{path}: unknown intent {intent!r}")
        for image, pattern in images.items():
            if not any(image in v.get("ci", {}).get("xfail", {}) for v in variants):
                raise ValueError(f"{path}: {intent} on {image}: no variant of that intent marks it xfail")
            try:
                compiled.setdefault(intent, {})[image] = re.compile(pattern, re.MULTILINE)
            except re.error as error:
                raise ValueError(f"{path}: {intent} on {image}: bad pattern {pattern!r} ({error})") from None
    return compiled


def classify(code, output, xfail, expected=None, check=""):
    """A finished case's (status, note). `xfail` is the variant's reason for the image (or None), `expected` its
    compiled ci/xfail-expect.json pattern (or None): an xfail with a pattern holds only when the output matches."""
    if code == 0:
        return ("XPASS", f"passes now: remove its xfail ({xfail})") if xfail else ("PASS", "")
    why = {10: "the recipe failed", 11: "the check failed: " + check, 124: "timed out"}.get(code, f"exit {code}")
    if not xfail:
        return "FAIL", why
    if expected is not None and not expected.search(output):
        return "FAIL", f"{why}, but not as expected (xfail needs output matching {expected.pattern!r}: {xfail})"
    return "XFAIL", xfail


def sudo_setup(native, distro_id):
    """The harness's sudo set-up for an image: SUDO_SETUP, or SUDO_SETUP_DERIVATIVE for a derivative of a family that
    has one (an Arch derivative)."""
    if native in SUDO_SETUP_DERIVATIVE and distro_id not in FAMILY_OWN_IDS.get(native, ()):
        return SUDO_SETUP_DERIVATIVE[native]
    return SUDO_SETUP[native]


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
                # Only the intents meshTerm asks with the ID_LIKE parent (lib.ID_LIKE_INTENTS) get it, and with it
                # the parent's family on an `unknown` pass (meshTerm 2.3.2's Containers recipe OS, lib.recipe_os).
                # An image with no systemd (`"systemd": false`, Devuan) asks lib.SYSTEMD_INHERITANCE without its
                # ID_LIKE, as the app does (ContainerHostFixes.systemdInheritance): never the inherited apt
                # rootless preparation, which needs dbus-user-session.
                tokens = [] if entry.get("systemd") is False and intent in lib.SYSTEMD_INHERITANCE else id_like
                selected, parent, inherited = lib.recipe_os(doc, intent, family, distro_id, tokens,
                                                            lib.CONTAINERS_CLASSIFIER_IDS,
                                                            lib.CONTAINERS_PARENT_FAMILIES)
                variant = lib.select(doc, intent, selected, distro_id, version_id, parent_id=parent,
                                     family_inherited=inherited)
                if variant is None:
                    continue
                if family == "any" or "any" in variant["families"]:
                    if family != "any":
                        continue  # an `any` line is tested once per image, in the `any` pass
                elif selected not in variant["families"]:
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
                    # `{{runid}}` (detached.* lines): a fresh 8-hex id per case, as the app makes one per tap.
                    runid = secrets.token_hex(4)
                    command = lib.render(variant["run"], sudo=(mode == "user"), user=user,
                                         packages=packages, port=ci.get("port"), proto=ci.get("proto"),
                                         group=ci.get("group"), path=ci.get("path"), intent=intent, runid=runid)
                    yield dict(image=image, mode=mode, family=family, intent=intent, variant=variant, native=native,
                               distro=distro_id, command=command, skip=why, runid=runid)


def su_form(bare):
    """The app's `su -c` body for `bare` (SuRoot.command, without the outer quoting): the root PATH line first,
    unless the line already starts with it as its own statement."""
    path = SU_PATH_LINE[:-2]
    if bare.startswith(path) and (bare[len(path):].startswith("; ") or bare[len(path):].startswith(" && ")):
        return bare
    return SU_PATH_LINE + bare


def run_case(doc, case):
    ci = case["variant"]["ci"]
    lines = ["set -e", "export DEBIAN_FRONTEND=noninteractive"]
    if case["native"] in IMAGE_REFRESH:
        lines.append(IMAGE_REFRESH[case["native"]])
    if case["mode"] == "su":
        # No sudoers entry: root's password (emptied here, so su asks for nothing) is the way to root.
        lines += [sudo_setup(case["native"], case.get("distro")), "passwd -d root >/dev/null"]
    if case["mode"] == "user":
        lines += [sudo_setup(case["native"], case.get("distro")),
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
            handle.write(su_form(case["command"]) if case["mode"] == "su" else case["command"])
            handle.write("\n")
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


# --systemd-pid1: the images, their family, and what each needs to boot systemd as PID 1 with a sudo user `mt`.
SYSTEMD_IMAGES = {"ubuntu:24.04": "apt", "rockylinux/rockylinux:9": "dnf"}
SYSTEMD_PREP = {
    "apt": "apt-get update -qq && apt-get install -y -qq systemd systemd-sysv sudo >/dev/null && rm -rf /var/lib/apt/lists/*",
    "dnf": "dnf install -y -q systemd sudo util-linux >/dev/null && dnf clean all >/dev/null",
}
SYSTEMD_RUN_FLAGS = ["--cgroupns=host", "--tmpfs", "/run", "--tmpfs", "/run/lock",
                     "-v", "/sys/fs/cgroup:/sys/fs/cgroup:rw"]


def systemd_image(image):
    """Build (once per run) `image` with systemd and the sudo user; returns the local tag."""
    native = SYSTEMD_IMAGES[image]
    tag = "mt-recipes-systemd:" + re.sub(r"[^a-z0-9.-]+", "-", image.lower())
    dockerfile = (f"FROM {image}\nRUN {SYSTEMD_PREP[native]} && useradd -m -s /bin/sh mt "
                  "&& echo 'mt ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/mt && chmod 0440 /etc/sudoers.d/mt\n"
                  "STOPSIGNAL SIGRTMIN+3\nCMD [\"/sbin/init\"]\n")
    with tempfile.TemporaryDirectory() as context:
        subprocess.run(["docker", "build", "-q", "-t", tag, "-f", "-", context], input=dockerfile.encode(),
                       check=True, stdout=subprocess.DEVNULL, timeout=1800)
    return tag


def systemd_case(doc, case, tag):
    """One detached.* case on a booted systemd container: (code, output, seconds), codes as run_case's."""
    ci = case["variant"]["ci"]
    detached = lib.is_detached(case["intent"])
    kind = case["intent"].split(".")[1]
    unit = f"meshterm-{kind}-{case.get('runid')}"
    lines = ["set -e", "export DEBIAN_FRONTEND=noninteractive"]
    if case["native"] in IMAGE_REFRESH:
        lines.append(IMAGE_REFRESH[case["native"]])
    prep = needs_line(doc, ci, case["native"])
    if prep:
        lines.append("{ " + prep + "; } >/dev/null 2>&1 || true")
    if ci.get("before"):
        lines.append(ci["before"] + " >/dev/null")
    user = "root" if case["mode"] == "root" else "mt"
    lines.append(f"export MT_USER={user}")
    lines.append("echo '--- recipe'")
    if case["mode"] == "user":
        lines.append("set +e; su mt -s /bin/sh -c 'cd && sh /t/recipe.sh' </dev/null; rc=$?; set -e")
    else:
        lines.append("set +e; (cd /root && sh /t/recipe.sh) </dev/null; rc=$?; set -e")
    lines.append('[ "$rc" = 0 ] || { echo "--- recipe exit $rc"; exit 10; }')
    # The unit ends (gone, or no longer active / activating), then systemd must have logged its clean end: the
    # systemd path ran (an exec failure there takes setsid, which this job must not pass).
    if detached:
        lines.append(f"i=0; while [ $i -lt 900 ]; do case \"$(systemctl is-active {unit} 2>/dev/null)\" in "
                     "active|activating|deactivating|reloading) i=$((i+1)); sleep 1;; *) break;; esac; done")
        lines.append(f"journalctl --no-pager -o cat -u {unit} | grep -q 'Deactivated successfully' "
                     f"|| {{ echo '--- {unit} did not run under systemd:'; journalctl --no-pager -o cat -u {unit} | tail -5; exit 11; }}")
    else:
        # An attached line: it ran in the foreground, so systemd-run's own transient unit has already ended.
        lines.append("journalctl --no-pager -o cat _PID=1 | grep -qE '^run-u[0-9]+[.]service: Deactivated successfully' "
                     "|| { echo '--- no systemd-run unit ended cleanly:'; journalctl --no-pager -o cat _PID=1 | grep run-u | tail -5; exit 11; }")
    lines.append("echo '--- check'")
    lines.append(f"sh -c {shlex.quote(ci['check'])} >/dev/null || {{ echo '--- check failed'; "
                 "tr '\\n' ' ' </var/log/meshterm/run.state; cat /var/log/meshterm/*.state; tail -5 /var/log/meshterm/*.log; exit 11; }")
    started = time.time()
    container = subprocess.run(["docker", "run", "-d", "--rm", *SYSTEMD_RUN_FLAGS, tag], check=True,
                               capture_output=True, text=True, timeout=300).stdout.strip()
    try:
        for _ in range(120):
            state = subprocess.run(["docker", "exec", container, "systemctl", "is-system-running"],
                                   capture_output=True, text=True).stdout.strip()
            if state in ("running", "degraded"):
                break
            time.sleep(0.5)
        else:
            return 1, f"systemd did not start (is-system-running: {state})", time.time() - started
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "recipe.sh"), "w") as handle:
                handle.write(case["command"] + "\n")
            with open(os.path.join(tmp, "case.sh"), "w") as handle:
                handle.write("\n".join(lines) + "\n")
            subprocess.run(["docker", "exec", container, "mkdir", "-p", "/t"], check=True)
            for name in ("recipe.sh", "case.sh"):
                subprocess.run(["docker", "cp", os.path.join(tmp, name), f"{container}:/t/{name}"], check=True,
                               stdout=subprocess.DEVNULL)
            subprocess.run(["docker", "exec", container, "chmod", "-R", "a+rX", "/t"], check=True)
        try:
            result = subprocess.run(["docker", "exec", container, "sh", "/t/case.sh"], stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, timeout=TIMEOUT)
            return result.returncode, result.stdout.decode("utf-8", "replace"), time.time() - started
        except subprocess.TimeoutExpired:
            return 124, "timed out", time.time() - started
    finally:
        subprocess.run(["docker", "rm", "-f", container], capture_output=True)


def systemd_main(doc, args):
    """--systemd-pid1: every detached.* and security-updates.* case on SYSTEMD_IMAGES (or --image), root and sudo
    user."""
    images = [i for i in SYSTEMD_IMAGES if not args.image or i in args.image]
    unknown = [i for i in (args.image or []) if i not in SYSTEMD_IMAGES]
    if unknown:
        print(f"FAIL  --systemd-pid1 knows {sorted(SYSTEMD_IMAGES)}, not {unknown}")
        return 1
    rows, failed = [], 0
    for image in images:
        native = SYSTEMD_IMAGES[image]
        cases = [c for c in plan(doc, {"images": [{"image": image, "families": [native]}]},
                                 argparse.Namespace(image=None, intent=args.intent, mode=args.mode, list=True))
                 if (lib.is_detached(c["intent"]) or c["intent"].startswith("security-updates."))
                 and c["mode"] in ("root", "user")]
        if not cases:
            print(f"FAIL  {image}: no detached.* line for {native}")
            failed += 1
            continue
        tag = None if args.list else systemd_image(image)
        for case in cases:
            label = f"{image:<14} {case['mode']:<4} systemd {case['intent']}"
            if case["command"] is None:
                rows.append((case, "FAIL", "does not render"))
                print(f"FAIL  {label}: does not render")
                failed += 1
                continue
            if args.list:
                print(f"RUN   {label}\n      {case['command']}")
                continue
            code, output, seconds = systemd_case(doc, case, tag)
            status, note = classify(code, output, None, None, case["variant"]["ci"]["check"])
            if status == "FAIL":
                failed += 1
                print(f"FAIL  {label} ({seconds:.0f} s): {note}\n      last {TAIL_LINES} lines of output:\n{tail(output)}",
                      flush=True)
                if os.environ.get("GITHUB_ACTIONS") == "true":
                    print(f"::error title=recipe FAIL::{image} {case['mode']} systemd {case['intent']}: {note}")
            else:
                print(f"{status:<5} {label} ({seconds:.0f} s)", flush=True)
            rows.append((case, status, note))
    if args.summary and not args.list:
        with open(args.summary, "a") as handle:
            handle.write("| Image | Mode | Path | Intent | Result | Note |\n|---|---|---|---|---|---|\n")
            for case, status, note in rows:
                handle.write(f"| {case['image']} | {case['mode']} | systemd PID 1 | `{case['intent']}` | {status} | "
                             f"{str(note).replace('|', '/')} |\n")
    print(f"summary: {len(rows) - failed} passed, {failed} failed (systemd PID 1)")
    return 1 if failed else 0


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
    # The Containers recipe OS with a draft idLike: a Fedora derivative's sudo lines render `wheel` (the dnf line's
    # ci.group), and an image row without systemd (Devuan) never gets the inherited apt rootless preparation.
    with open(os.path.join(ROOT, "recipes.json"), "rb") as handle:
        raw = json.loads(handle.read())
    raw["idLike"] = ["arch", "debian", "ubuntu", "fedora"]
    doc = lib.load(json.dumps(raw).encode())
    args = argparse.Namespace(image=None, intent=None, mode=None, list=True)

    def cases(entry):
        return [c for c in plan(doc, {"images": [dict(entry, families=["unknown"])]}, args) if c["command"]]

    grant = [c["command"] for c in cases({"image": "t/ultramarine", "id": "ultramarine", "idLike": ["fedora"]})
             if c["intent"] in ("sudo.grant", "sudo.install")]
    if not grant or not all("-aG wheel " in c and "-aG sudo " not in c for c in grant):
        print(f"self-test FAIL: a fedora-parented host's sudo lines: {grant!r}")
        failures += 1
    for systemd, want in [(True, True), (False, False)]:
        got = any(c["intent"] == "engine.docker.rootless-prepare" and "dbus-user-session" in c["command"]
                  for c in cases({"image": "t/devuan", "id": "devuan", "idLike": ["debian"], "systemd": systemd}))
        if got != want:
            print(f"self-test FAIL: devuan systemd={systemd}: apt rootless preparation {got}, expected {want}")
            failures += 1
    # An Arch derivative's sudo set-up upgrades fully; archlinux:latest's and every other family's is unchanged.
    for native, distro, want in [("pacman", "manjaro", SUDO_SETUP_DERIVATIVE["pacman"]),
                                 ("pacman", "cachyos", SUDO_SETUP_DERIVATIVE["pacman"]),
                                 ("pacman", "arch", SUDO_SETUP["pacman"]), ("pacman", "archlinux", SUDO_SETUP["pacman"]),
                                 ("apt", "devuan", SUDO_SETUP["apt"]), ("apk", "alpine", SUDO_SETUP["apk"])]:
        if sudo_setup(native, distro) != want:
            print(f"self-test FAIL: sudo_setup({native!r}, {distro!r})")
            failures += 1
    # The su form: the app's root PATH line first, never twice (SuRoot.command).
    for bare, want in [("dpkg --configure -a", SU_PATH_LINE + "dpkg --configure -a"),
                       (SU_PATH_LINE + "x", SU_PATH_LINE + "x"),
                       ('PATH="$PATH:/usr/sbin:/sbin" && x', 'PATH="$PATH:/usr/sbin:/sbin" && x'),
                       ('PATH="$PATH:/usr/sbin:/sbin"x', SU_PATH_LINE + 'PATH="$PATH:/usr/sbin:/sbin"x')]:
        if su_form(bare) != want:
            print(f"self-test FAIL: su_form({bare!r}): {su_form(bare)!r}")
            failures += 1
    # An xfail with an expected message holds only for that failure; without one, any failure is the xfail.
    devuan = re.compile("Unsupported distribution 'devuan'", re.MULTILINE)
    for code, output, xfail, expected, want in [
            (10, "x\nERROR: Unsupported distribution 'devuan'\n--- recipe exit 1", "why", devuan, "XFAIL"),
            (10, "curl: (6) Could not resolve host: get.docker.com\n--- recipe exit 6", "why", devuan, "FAIL"),
            (11, "", "why", devuan, "FAIL"),
            (124, "timed out", "why", devuan, "FAIL"),
            (10, "anything", "why", None, "XFAIL"),
            (0, "", "why", devuan, "XPASS"),
            (10, "Unsupported distribution 'devuan'", None, None, "FAIL"),
            (0, "", None, None, "PASS")]:
        got = classify(code, output, xfail, expected, "check")[0]
        if got != want:
            print(f"self-test FAIL: classify({code}, {output!r}, xfail={xfail!r}, expected={expected and expected.pattern!r}): {got}, expected {want}")
            failures += 1
    # The repository's own ci/xfail-expect.json loads (every entry backed by an xfail), and a stray entry is refused.
    try:
        real = load_xfail_expect(lib.load(open(os.path.join(ROOT, "recipes.json"), "rb").read()))
        if "devuan/devuan:latest" not in real.get("engine.docker.install-script", {}):
            print("self-test FAIL: ci/xfail-expect.json has no Devuan get.docker.com pattern")
            failures += 1
    except ValueError as error:
        print(f"self-test FAIL: ci/xfail-expect.json: {error}")
        failures += 1
    with tempfile.TemporaryDirectory() as tmp:
        for body, ok in [({"expect": {"engine.docker.install-script": {"debian:12": "x"}}}, False),
                         ({"expect": {"no.such.intent": {"debian:12": "x"}}}, False),
                         ({"expect": {"engine.docker.install-script": {"devuan/devuan:latest": "("}}}, False),
                         ({"expect": {"engine.docker.install-script": {"devuan/devuan:latest": "x"}}}, True)]:
            stray = os.path.join(tmp, "expect.json")
            with open(stray, "w") as handle:
                json.dump(body, handle)
            try:
                load_xfail_expect(doc, stray)
                refused = False
            except ValueError:
                refused = True
            if refused == ok:
                print(f"self-test FAIL: load_xfail_expect({body!r}): refused={refused}")
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
    parser.add_argument("--self-test", action="store_true", help="test the os-release parser, the xfail patterns and exit")
    parser.add_argument("--systemd-pid1", action="store_true",
                        help="run the detached.* lines on images booted with systemd as PID 1 (SYSTEMD_IMAGES)")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    with open(os.path.join(ROOT, "recipes.json"), "rb") as handle:
        doc = lib.load(handle.read())
    if args.systemd_pid1:
        return systemd_main(doc, args)
    with open(os.path.join(ROOT, "ci", "images.json")) as handle:
        matrix = json.load(handle)
    try:
        expect = load_xfail_expect(doc)
    except ValueError as error:
        print(f"FAIL  {error}")
        return 1

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
        status, note = classify(code, output, case["variant"]["ci"].get("xfail", {}).get(case["image"]),
                                expect.get(case["intent"], {}).get(case["image"]), case["variant"]["ci"]["check"])
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
