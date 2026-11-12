# meshterm-recipes

Signed host recipes (install/start/fix commands) for meshTerm.

The install, fix and start commands meshTerm shows for a server (install tmux, a container engine, Compose, git,
curl and friends; start an engine; turn on Podman's socket), as signed DATA, so a command that a Linux distribution
broke can be fixed without an App Store release.

- `recipes.json`: the recipes (format schema 1). Published at
  `https://ag-studio-apps.github.io/meshterm-recipes/v1/recipes.json` (what apps from 2.3 fetch) and, with the same
  bytes and signature, at the root `recipes.json` (earlier TestFlight builds, kept while any is in use), each with its
  minisign signature `recipes.json.minisig`. A future schema 2 would be `recipes-v2.json`, published to `v2/` and
  signed on its own, so schema-1 apps keep getting serials beside it.
- `recipes.schema.json`: the format, as documentation. `scripts/validate.py` is authoritative (it is the app's own
  rules, in Python).
- `keys/`: the public keys the app pins. They are the template catalogue's keys (meshdeck-docs), reused under a
  different signed kind.

## What a recipe can and cannot do

A recipe is command TEXT for an intent on an OS. The app decides everything else:

- **when** a fix is offered (its own probes: is tmux there, is the engine running, which distro is this);
- **privilege**: root runs the bare form, a sudoer the sudo form, a host with no sudo gets `su -c '…'` with the root
  password, an account in no admin group gets the ask-the-admin note. A recipe marks where privilege goes with
  `{{sudo}}`; it may not write `sudo` or `su` itself;
- staging long commands, the one-tap completion marker, and showing the whole command before it runs;
- the safety-critical scripts (the sshd forwarding edit with rollback, the PATH block, Codex's server files, sudo
  set-up): never in this file.

The app accepts a published file only when: the signature verifies against the pinned keys; the trusted comment is
`recipes=host-recipes version=<serial> date=<date>` (a template-catalogue signature never passes); the serial is at
or above both the app's bundled copy and the last file it accepted (the same serial only with identical bytes); the
schema is 1; every rule in `scripts/validate.py` holds; and nothing the app's bundled copy has was dropped (an
intent, a family-level line, a package). Otherwise it keeps the copy it has. Devices check at launch and on
foreground, at most every 12 hours (1 hour after a failure).

## The format

```json
{
  "kind": "host-recipes", "schema": 1, "serial": 2, "date": "2026-10-20",
  "packages": { "procps": { "apt": "procps", "dnf": "procps-ng", "yum": "procps-ng", "apk": "procps-ng" } },
  "intents": {
    "tmux.install": [
      { "families": ["apt"], "run": "{{sudo}}apt-get update && {{sudo}}apt-get install -y tmux",
        "ci": { "check": "command -v tmux" } }
    ]
  }
}
```

- **families**: `apt`, `dnf`, `yum`, `apk`, `pacman`, `zypper`, `macos`, `unknown` (a Linux the app could not name:
  the line must pick a package manager at run time), `any` (init-system lines such as `systemctl`).
- **ids** (optional): `/etc/os-release` `ID` values. **versions** (optional): `{"min": "22.04", "below": "24.04"}`
  over `VERSION_ID` (min inclusive, below exclusive). The most specific matching variant wins: ids and versions,
  then ids, then the inherited parent's ids (`idLike` below), then versions, then the family, then `any`; file order
  breaks a tie. Today only the agents' checks know
  a host's VERSION_ID; the tmux and Containers checks know the ID only, so a version-ranged line needs an id- or
  family-level line beside it.
- **run**: one line of printable ASCII, at most 2,000 characters. Placeholders, and only these:
  - `{{sudo}}` opens a command (at the start, or after `&& `, `; `, `then `, `| `): `sudo ` or nothing;
  - `{{user}}` the SSH user, as one safe shell word (`$USER` when the app names no one);
  - `{{packages}}` the package names (for `packages.install`, `podman.rootless-prerequisites`, `sudo.install`,
    `security-updates.apt`, `security-updates.apk` and `security-updates.dnf`; in `sudo.install` only right after an
    install verb or as `p="{{packages}}"`; in a `security-updates.*` intent only right after an upgrade verb, as whole
    words: `--only-upgrade -y `, `upgrade -y ` or `upgrade `, at the start or after a space, never `--upgrade ` or
    `foo-upgrade `, and with no `add` / `install` / `reinstall` / `localinstall` / `groupinstall` word anywhere before
    it except apt-get's `install --only-upgrade -y ` in `security-updates.apt`, meshTerm 2.4). Names are
    `[a-z0-9][a-z0-9.+_-]*`; `security-updates.dnf` alone also takes capitalised rpm names (`NetworkManager`,
    `perl-DBI`: `[A-Za-z0-9][A-Za-z0-9.+_-]*`, in its `{{packages}}` value and `ci.packages`);
  - `{{port}}` (1-65535) and `{{proto}}` (`tcp` / `udp`) for firewall lines;
  - `{{group}}` the admin group (`sudo` / `wheel`), only right after `-aG ` / `-G ` or as
    `addgroup {{user}} {{group}}` (the word `sudo` itself is refused anywhere in a run);
  - `{{path}}` an absolute path of `[A-Za-z0-9._/+-]` (no `//`, no `/.`), such as rootlesskit's.

  The app fills them in ONE pass, so a value is never read as a placeholder.
- **Forward compatibility**: a variant with a key this format does not know (a later selector), a well-formed
  placeholder it does not know, or `minSchema` above 1 is UNUSABLE for today's apps, not a refused file: where such a
  variant would be chosen (it scores at least as high as the best usable one), the app uses its bundled line for that
  intent and OS. Every security rule (privilege words, ASCII, placement of the known placeholders, selectors) still
  refuses the whole file.
- **idLike** (optional, top level; meshTerm 2.3.2+, older apps ignore it): the parents an unnamed derivative may
  inherit lines from through os-release `ID_LIKE`, e.g. `["arch", "debian", "ubuntu", "fedora"]` (distinct ids, at
  most 16). Absent or `[]` turns inheritance off: that is the kill switch, and narrowing the list is how a bad
  inheritance is undone (a hosted file need not keep the bundled file's list). A distro named by ANY variant's `ids`,
  or by the app's own classifier (`recipes_lib.CONTAINERS_CLASSIFIER_IDS`), never inherits. Otherwise the `ID_LIKE`
  tokens are walked in order: a token on the list is the parent; a FAMILY ROOT off the list
  (`recipes_lib.ID_LIKE_FAMILY_ROOTS`: alpine, arch, centos, debian, fedora, gentoo, mandriva, opensuse, rhel,
  slackware, suse, ubuntu; the app holds the same list) stops the walk and the host gets no parent; any other token (a
  named derivative such as `linuxmint`, or an id nobody recognises) is skipped. So `ID_LIKE="linuxmint ubuntu"`
  inherits `ubuntu` and `ID_LIKE="rhel centos fedora"` inherits nothing while `rhel` is off the list. The parent is
  resolved from the file in use (the id and the tokens trimmed and lower-cased), and an `ids` line naming it matches
  as 6 (between an id match, 8, and a version range, 2) but only without `versions`; an intent with a versioned line
  naming the parent does not use the parent at all. With the parent, a host whose own family is `unknown` also takes
  the parent's recipe FAMILY (`recipes_lib.CONTAINERS_PARENT_FAMILIES`, the app classifier's families: debian/ubuntu
  -> apt, fedora -> dnf, alpine -> apk; arch has none and stays `unknown`), so family-level lines apply (elementary ->
  the apt lines), except version-only ones (their range is the family's distributions'). The family is resolved with
  the parent, from the same file, so `"idLike": []` turns both off. The parent applies ONLY to the intents
  `recipes_lib.ID_LIKE_INTENTS` lists (meshTerm 2.3.2: the Containers intents, `engine.*`, `compose.*`, `podman.*`,
  `git.install`, `ca-certificates.install`, `sudo.install`, `sudo.grant`; tmux, agents, packages, sshd, firewall and
  the rest follow in 2.3.3); the format cases' `idLikeIntents` pins the app to the same list. So naming a derivative
  in one intent moves EVERY intent of it off its parent's lines: `validate.py --declared` requires `{"named": "<id>"}`
  for an id `compat/distros.json` lists with an `idLike` (classifier ids aside), `{"unnamed": "<id>"}` for one that is
  no longer named (it starts inheriting), and a change to `idLike` itself is declared as `{"kind": "idLike"}`. From
  serial 11 a `--declared` run without `compat/distros.json` (or `--distros`) FAILS. Engine-side guard (in the app,
  not the data): meshTerm asks `recipes_lib.SYSTEMD_INHERITANCE` (`engine.docker.rootless-prepare`) WITHOUT the host's
  ID_LIKE unless its probe saw systemd, so Devuan never gets the inherited apt preparation (it installs
  `dbus-user-session`, which Devuan 6 has no candidate for). `run-recipes.py` mirrors it for an image row with
  `"systemd": false`. The sudo recipes' `{{group}}` follows the family the line was selected by (a Fedora derivative
  on the dnf line: `wheel`), as the variant's `ci.group` does.
- **admin** (optional): needs an administrator even without `{{sudo}}` (Docker's install script, which asks for
  sudo itself).
- **packages**: package id -> family -> name, for `packages.install`. A family with no entry needs nothing.
- **ci**: for the distro matrix only (the app ignores it): `check` (a shell assertion run as root after the recipe;
  `$MT_USER` is the user it ran as) or `skip` (why it cannot run in a container), and optionally `needs` (package ids
  installed first, as root), `before` (a shell line run first, as root), `packages` (the `{{packages}}` value),
  `rootOnly` / `userOnly` (why one pass is skipped), `skipOn` and `xfail` (image -> reason; an xfail is reported,
  never red, and an XPASS asks for the entry to go; `ci/xfail-expect.json` can pin the message an xfail was measured
  with, intent -> image -> regular expression, and then any other failure there is red), and `port`, `proto`, `group`,
  `path` (the values to render with). `{{user}}` renders as the case's own user (`mt` in the sudo-user pass, `root` in
  the root pass).
- **Agent and herdr lines** (`agent.*`, `herdr.install`; `scripts/validate.py`): no `{{sudo}}` or `admin`, https URLs
  only, never `/tmp` or a download piped into a shell; an official installer is downloaded with
  `-o ~/.mt-install-<name>.sh`, run, and the line ends `&& rm -f ~/.mt-install-<name>.sh`; Codex's keeps
  `CODEX_NON_INTERACTIVE=1`.
- **Security updates lines** (meshTerm 2.4, the host Security updates sheet): `tailscale.update`,
  `tailscale.update.detached` and `tailscale.auto-update` (Tailscale's own updater; Alpine through apk, Arch through
  a full `pacman -Syu`); `security-updates.apt`, `security-updates.apk` and `security-updates.dnf` (upgrade only the
  installed packages the host's package check flagged, with the `{{packages}}` rules above); and `server.restart`,
  which restarts the server so an installed kernel update takes effect. `server.restart` is never part of Install
  Updates: the sheet shows it as its own Restart Server button, behind a confirmation. Its lines are
  `{{sudo}}systemctl reboot || {{sudo}}shutdown -r now` (`shutdown -r now` where `systemctl` is missing or refuses)
  and `{{sudo}}reboot` on Alpine. No CI runs it: the container matrix skips it (it would end the container or the
  runner) and the VM tier (`scripts/vm_test.py`, branch `vm-tests-s12`) has no case for it yet; it reboots its VMs
  with its own line. Sudo can ask twice: the fallback is a second `sudo`, so when the first one ends without a cached
  credential (the password was mistyped until sudo gave up, or the host caches none, `timestamp_timeout=0`), the
  second asks for the password again before `shutdown -r now` runs. Root runs the bare form and is never asked.
- **Detached runs** (serial 13, meshTerm 2.5: `detached.updates.apt`, `.dnf`, `.apk`, `detached.finish.apt`): Install
  Updates and Finish Update run on the server, away from the SSH connection, so a dropped link (a tailscaled or sshd
  restart during the upgrade) cannot stop dpkg half way. The template has ONE shape, checked exactly by the
  validators (`recipes_lib.check_detached`, meshTerm's `HostRecipeTemplate` the twin):
  `{{sudo}}sh -c '<launcher>' meshterm-<kind>-{{runid}} {{user}} '<body>'`, plus ` {{packages}}` for an `updates`
  run. No placeholder inside the quoted scripts (values arrive as positional arguments); no `${` or `$$` in the body
  (systemd expands both in a transient unit's arguments); `"$@"` (the package names) once in the body right after an
  upgrade verb; `{{runid}}` (8 lowercase hex, the app's run id) in no other intent. The launcher is byte-identical
  across the four (`validate.py` checks it) and a detached run is at most 1,950 characters. It claims the run as root
  (`/var/log/meshterm/<kind>-<id>.state`, `run.state`, the lock `/run/meshterm-pkg.lock`, a symlink naming the run;
  busy = exit 75), then starts the body with `systemd-run -p Type=exec` (an exec failure is synchronous and falls
  through to `setsid`) or `setsid`; with neither it writes `fail=start` and exits 71 (the app then runs the plain line
  attached). The body exports `NEEDRESTART_SUSPEND=1`: measured on Ubuntu 24.04 with the release-pocket needrestart
  (LP #2067482), needrestart otherwise restarts the unit mid-run. The apt bodies (`detached.updates.apt`,
  `detached.finish.apt`) then put the service restarts back: after `rc=` and `ended=` are written, and only when the
  status is 0, `systemd-run --on-active=5 --collect -q sh -c "needrestart -m u -l||needrestart -l" 2>/dev/null`
  starts needrestart in a transient timer unit of its own, in the server's own needrestart mode (libraries only: no
  kernel or microcode hint; see "Which restarts" below). It fires after the body has exited and released the lock
  (5 s plus the timer's default accuracy, so up to about a minute), so it can never restart the run's own unit,
  never changes `rc=` and never holds `/run/meshterm-pkg.lock`. Without systemd, or without needrestart,
  `systemd-run` fails quietly and nothing happens.
  The container matrix runs the setsid path; the `systemd` job (`run-recipes.py --systemd-pid1`, ubuntu:24.04 and
  Rocky 9 booted with systemd as PID 1) runs the systemd path of the `detached.*` lines and of the attached
  `security-updates.apt` / `.dnf` lines, and both gate signing.
- **Which restarts: the server's own needrestart setting** (James 2026-11-12, "Follow server setting"). The
  follow-up runs what the server's own APT hook would have run, so a restart happens exactly when an attended
  `apt upgrade` on that server would restart. `needrestart -m u` is Ubuntu's hook (`apt-pinvoke -m u`): Ubuntu mode
  restarts automatically unless `/etc/needrestart/needrestart.conf` or `conf.d/*.conf` sets `$nrconf{restart}` (or
  a UI), and then that mode wins (3.6-7ubuntu4.1 and later, LP #2068543; the release-pocket `3.6-7ubuntu4` forces
  automatic restarts in Ubuntu mode whatever the conf says, exactly as its own hook does). Debian's needrestart has
  no Ubuntu mode: it exits with `ERROR: Unknown UI mode 'u'!` (in the journal) before doing anything, and the plain
  `needrestart -l` runs in the configured mode, stock `i`. It never prompts: the unit's stdin is `/dev/null` and its
  output the journal, and with no terminal needrestart turns `i` into `l` (list only, in the journal); `a` restarts.
  No `-f noninteractive`: with `-l` and a mode of `l` or `a` needrestart asks no debconf question (debconf logs
  `unable to initialize frontend: Dialog` and falls back, harmless). Measured in Docker (systemd PID 1, a service
  mapping a library an upgrade replaces), `detached.updates.apt`, `detached.finish.apt` and `security-updates.apt`:
  Ubuntu 24.04 `3.6-7ubuntu4.5` and `3.6-7ubuntu4` stock restart it; `4.5` with `$nrconf{restart} = 'l'` or `'i'`
  lists it and keeps its PID (`3.6-7ubuntu4` with `'l'` restarts, as above); Debian 12 `3.6-4+deb12u3` stock and
  with `'l'` lists it and keeps its PID, with `'a'` restarts it; every needrestart unit ends (no leftover
  `run-r*` unit), `rc=` and `ended=` are unchanged, and a session cgroup SIGKILLed mid-install leaves `dpkg --audit`
  empty.
- **Why the session is not the place for an upgrade** (2026-11-12): the Pharos failure (2026-11-11) was not a SIGHUP
  (apt and dpkg ignore it): the session came over Tailscale SSH, whose sessions live in tailscaled's own service
  cgroup, and the tailscale package's postinst restarted tailscaled, so systemd killed the whole cgroup, apt and dpkg
  with it, leaving dpkg half configured. Serial 13's attached lines therefore start the package tool with `systemd-run
  --wait --pipe --collect --quiet` where systemd runs (`r=; [ -d /run/systemd/system ] && command -v systemd-run
  >/dev/null && r="..."; ... {{sudo}}$r apt-get ...`): the output still streams to the session and the exit status is
  the line's, but the tool is in its own transient unit, outside the session's tree and cgroup. `security-updates.apt`
  sets `DEBIAN_FRONTEND=noninteractive NEEDRESTART_SUSPEND=1` there and, after a successful install on a host with
  `/usr/sbin/needrestart`, starts the same needrestart timer unit as the detached bodies (`{{sudo}}systemd-run
  --on-active=5 --collect --quiet sh -c "needrestart -m u -l||needrestart -l" || :`), so the marker and "Done" reach
  the app before any service restarts (a restarted tailscaled can still drop the session then; the install is already
  done). Measured in Docker (ubuntu:24.04 booted with systemd, an SSH server in its own service cgroup restarted by a
  package's postinst): dpkg ends clean; a daemon mapping an upgraded library (libssl, and a fake library) is restarted
  by the follow-up with needrestart `3.6-7ubuntu4` and `3.6-7ubuntu4.5` (listed, not restarted, by stock
  `3.6-4+deb12u3` on Debian 12); apt runs once; a failing package gives the marker 100 and no follow-up; no
  needrestart or no systemd is silent. When the session is killed mid-install, apt still finishes in its unit, but the
  follow-up (in the dead shell) does not run, so the restarts wait for the next run or Restart Server. Without systemd
  both lines are the serial 12 lines (apt with the confdef / confold options). `security-updates.dnf` takes the same
  `systemd-run` form (rpm already defers SIGTERM during a transaction, but a unit stop escalates to SIGKILL after its
  timeout); no needrestart step there. 2.4.0 / 2.4.1 accept both (their compiled readers and `compat_check`).
  `packages.finish-interrupted` is Finish Update's plain line (shown, copied, Open Terminal).

## How to update a recipe safely

1. Branch, and change `recipes.json`. Raise `serial` by one and set `date` to today. A file that changed keeps no
   serial: the app refuses the same serial with different bytes, and a lower one.
2. Never remove an intent, a family from a family-level line, or a package. To undo an id- or version-specific fix,
   remove that variant; the family line takes over.
3. Prefer the narrowest selector that fixes it: an `ids` (and `versions`) variant beside the family line, so every
   other distro keeps the line that works.
4. Give the new variant a `ci.check` that proves the result (`command -v tmux`), not just a zero exit.
5. Run locally, one container at a time:

   ```sh
   python3 scripts/validate.py --previous-ref origin/main
   python3 scripts/validate.py --self-test
   python3 scripts/run-recipes.py --intent tmux.install           # the intent you changed, every image
   python3 scripts/run-recipes.py --list                          # what would run, without Docker
   ```

6. Open a pull request for the record. It starts no workflow: the publish run is the test.
7. Merge. `Publish recipes` validates against the main it replaces (incl. the declared-changes check), runs every
   recipe on the fresh-distro matrix as root and as a sudo user, then waits for the `recipes-signing` approval. Read
   the job summary (the diff since the deployed commit; a banner if the pipeline itself changed), approve, and the
   signed pair is deployed and smoke-tested. Devices pick it up within 12 hours of their next launch.

A new intent or placeholder needs an app release first: today's apps ignore intents they don't know and refuse an
unknown placeholder. A schema bump stops every older app from updating, so keep schema 1 additive.

## Signing

`publish.yml` is the catalogue's pipeline (meshdeck-docs) for this file: the primary key lives only in the
`recipes-signing` environment (a required reviewer, who may approve their own run; no admin bypass; `main` only: the
sign job refuses to run otherwise); the trusted comment is
`recipes=host-recipes version=<serial> date=<date> commit=<sha>`. A push that changes nothing in `recipes.json` reuses
the live signature without approval.

If the primary key is lost or leaked: sign offline with the emergency key (`scripts/sign-emergency.sh --key …`,
which validates, checks the serial is above the live one and verifies the result), commit `recipes.json` and
`recipes.json.minisig` together, push and approve. Delete `recipes.json.minisig` in the next change. Key rotation
moves together across this repository's `keys/` and workflow ids, meshdeck-docs, and the app's `CatalogTrust`.

Setup is done for this repository (Pages from GitHub Actions; `recipes-signing` with its reviewer, main only, and
the `MINISIGN_KEY` / `MINISIGN_PASSWORD` secrets). `scripts/setup-recipes-signing.sh` is for re-creating it on a
FRESH repository only.

## The app side

meshTerm `docs/host-recipes.md`: `MeshTermFailures/HostRecipes` (model, rules, store, bundled snapshot
`RecipesSnapshot/recipes.json`), `MeshTermContainerEngine/Recipes/HostRecipesUpdater.swift` (fetch, verify, cache),
Settings > Developer > Host recipes (which serial is in use). Every release copies the then-current `recipes.json`
into the app as its bundled snapshot.
