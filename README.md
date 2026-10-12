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
  then ids, then versions, then the family, then `any`; file order breaks a tie. Today only the agents' checks know
  a host's VERSION_ID; the tmux and Containers checks know the ID only, so a version-ranged line needs an id- or
  family-level line beside it.
- **run**: one line of printable ASCII, at most 2,000 characters. Placeholders, and only these:
  - `{{sudo}}` opens a command (at the start, or after `&& `, `; `, `then `, `| `): `sudo ` or nothing;
  - `{{user}}` the SSH user, as one safe shell word (`$USER` when the app names no one);
  - `{{packages}}` the package names (for `packages.install`, `podman.rootless-prerequisites` and `sudo.install`; in
    `sudo.install` only right after an install verb or as `p="{{packages}}"`);
  - `{{port}}` (1-65535) and `{{proto}}` (`tcp` / `udp`) for firewall lines;
  - `{{group}}` the admin group (`sudo` / `wheel`), only right after `-aG ` / `-G ` or as `addgroup {{user}} {{group}}`
    (the word `sudo` itself is refused anywhere in a run);
  - `{{path}}` an absolute path of `[A-Za-z0-9._/+-]` (no `//`, no `/.`), such as rootlesskit's.

  The app fills them in ONE pass, so a value is never read as a placeholder.
- **Forward compatibility**: a variant with a key this format does not know (a later selector), a well-formed
  placeholder it does not know, or `minSchema` above 1 is UNUSABLE for today's apps, not a refused file: where such a
  variant would be chosen (it scores at least as high as the best usable one), the app uses its bundled line for that
  intent and OS. Every security rule (privilege words, ASCII, placement of the known placeholders, selectors) still
  refuses the whole file.
- **admin** (optional): needs an administrator even without `{{sudo}}` (Docker's install script, which asks for
  sudo itself).
- **packages**: package id -> family -> name, for `packages.install`. A family with no entry needs nothing.
- **ci**: for the distro matrix only (the app ignores it): `check` (a shell assertion run as root after the recipe;
  `$MT_USER` is the user it ran as) or `skip` (why it cannot run in a container), and optionally `needs` (package ids
  installed first, as root), `before` (a shell line run first, as root), `packages` (the `{{packages}}` value),
  `rootOnly` / `userOnly` (why one pass is skipped), `skipOn` and `xfail` (image -> reason; an xfail is reported, never
  red, and an XPASS asks for the entry to go), and `port`, `proto`, `group`, `path` (the values to render with).
  `{{user}}` renders as the case's own user (`mt` in the sudo-user pass, `root` in the root pass).
- **Agent and herdr lines** (`agent.*`, `herdr.install`; `scripts/validate.py`): no `{{sudo}}` or `admin`, https URLs
  only, never `/tmp` or a download piped into a shell; an official installer is downloaded with
  `-o ~/.mt-install-<name>.sh`, run, and the line ends `&& rm -f ~/.mt-install-<name>.sh`; Codex's keeps
  `CODEX_NON_INTERACTIVE=1`.

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

6. Open a pull request. `Test recipes` validates against `main` and runs every recipe on debian:12, ubuntu:22.04,
   ubuntu:24.04, fedora:latest, rockylinux/rockylinux:9 and alpine:3.20, as root and as a sudo user, in fresh containers.
7. Merge. `Publish recipes` runs the matrix again, then waits for the `recipes-signing` approval. Read the job
   summary (the diff since the deployed commit; a banner if the pipeline itself changed), approve, and the signed
   pair is deployed and smoke-tested. Devices pick it up within 12 hours of their next launch.

A new intent or placeholder needs an app release first: today's apps ignore intents they don't know and refuse an
unknown placeholder. A schema bump stops every older app from updating, so keep schema 1 additive.

## Signing

`publish.yml` is the catalogue's pipeline (meshdeck-docs) for this file: the primary key lives only in the
`recipes-signing` environment (a required reviewer, who may approve their own run; no admin bypass; `main` only: the sign job
refuses to run otherwise); the trusted comment is `recipes=host-recipes version=<serial> date=<date> commit=<sha>`.
A push that changes nothing in `recipes.json` reuses the live signature without approval.

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
