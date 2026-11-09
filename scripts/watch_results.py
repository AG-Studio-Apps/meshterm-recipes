"""The machine-readable result file every recipes-watch job writes (docs/recipes-watch.md).

One JSON object per job, uploaded as an artifact named `watch-*`. A collector on the maintainers' side (outside
this repository) reads them and files, comments on or closes issues. Nothing in here talks to an issue tracker, and
nothing here needs a token: the files hold public data only (recipe text, image names, public URLs, hashes).

    {
      "format": "recipes-watch/1",
      "tier": "container" | "early" | "runner" | "vm" | "compat" | "validate" | "live" | "install-url",
      "source": "main" | "live" | ...,          what was tested (the checkout, the published file)
      "recipes": {"serial": 3, "sha256": "..."},  the recipes file tested, when there is one
      "commit": "<sha>", "run": "<run id>", "job": "<job label>", "created": "<UTC>",
      "covers": ["compat:app-2.3.0"],           checks this file evaluated COMPLETELY (a check listed here with no
                                                failing record means every fingerprint of that check passed)
      "results": [
        {"check": "container", "intent": "tmux.install", "target": "debian:12", "mode": "root",
         "status": "pass" | "fail" | "error" | "xfail" | "xpass" | "skip" | "changed" | "info",
         "command": "...", "output": "<short tail>", "detail": "..."}
      ]
    }

A record's FINGERPRINT is (check, intent, target): one issue per fingerprint. `mode` and `source` are detail, not
identity, so the root and sudo-user passes of one recipe on one image share an issue, as do main and live.
"""
import datetime
import hashlib
import json
import os
import re

FORMAT = "recipes-watch/1"
STATUSES = {"pass", "fail", "error", "xfail", "xpass", "skip", "changed", "info"}
OUTPUT_LIMIT = 1500
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07]*\x07|\r")


def tail(text, limit=OUTPUT_LIMIT):
    text = ANSI.sub("", text or "")
    return text if len(text) <= limit else "..." + text[-limit:]


def recipes_meta(path):
    """{serial, sha256} of a recipes file, or None when it cannot be read."""
    try:
        with open(path, "rb") as handle:
            data = handle.read()
        serial = json.loads(data.decode("utf-8")).get("serial")
    except (OSError, ValueError, AttributeError):
        return None
    return {"serial": serial, "sha256": hashlib.sha256(data).hexdigest()}


def new(tier, source="main", recipes=None, job=None, covers=None):
    return {
        "format": FORMAT,
        "tier": tier,
        "source": source,
        "recipes": recipes_meta(recipes) if recipes else None,
        "commit": os.environ.get("GITHUB_SHA", ""),
        "run": os.environ.get("GITHUB_RUN_ID", ""),
        "job": job or os.environ.get("GITHUB_JOB", ""),
        "created": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "covers": list(covers or []),
        "results": [],
    }


def add(doc, check, status, intent="", target="", mode="", command="", output="", detail=""):
    if status not in STATUSES:
        raise ValueError(f"unknown status {status}")
    record = {"check": check, "intent": intent or "", "target": target or "", "status": status}
    if mode:
        record["mode"] = mode
    if command:
        record["command"] = tail(command, 2500)
    if output:
        record["output"] = tail(output)
    if detail:
        record["detail"] = tail(str(detail), 600)
    doc["results"].append(record)
    return record


def write(doc, path):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(doc, handle, indent=1, sort_keys=False)
        handle.write("\n")


def fallback(path, tier, source, job, why):
    """The result a job writes when its script died before writing one (an `if: always()` step)."""
    if os.path.exists(path):
        return False
    doc = new(tier, source=source, job=job)
    add(doc, "harness", "error", target=job, detail=why)
    write(doc, path)
    return True


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="write a result file from a workflow step")
    sub = parser.add_subparsers(dest="command", required=True)
    fb = sub.add_parser("fallback", help="an error result, only when the job wrote none (an `if: always()` step)")
    fb.add_argument("--out", required=True)
    fb.add_argument("--tier", required=True)
    fb.add_argument("--source", default="main")
    fb.add_argument("--job", required=True)
    fb.add_argument("--why", default="the job ended without writing its result file")
    rec = sub.add_parser("record", help="one record from a step's outcome (success / failure / anything else)")
    rec.add_argument("--out", required=True)
    rec.add_argument("--tier", required=True)
    rec.add_argument("--check", required=True)
    rec.add_argument("--outcome", required=True, help="the step's outcome: success, failure, cancelled, skipped")
    rec.add_argument("--intent", default="")
    rec.add_argument("--target", default="")
    rec.add_argument("--source", default="main")
    rec.add_argument("--recipes")
    rec.add_argument("--output-file", help="a log whose tail goes into the record")
    args = parser.parse_args()
    if args.command == "fallback":
        print(("wrote fallback " if fallback(args.out, args.tier, args.source, args.job, args.why) else "kept ")
              + args.out)
        sys.exit(0)
    status = {"success": "pass", "failure": "fail"}.get(args.outcome, "error")
    text = ""
    if args.output_file and os.path.exists(args.output_file):
        with open(args.output_file, errors="replace") as handle:
            text = handle.read()
    result = new(args.tier, source=args.source, recipes=args.recipes, covers=[args.check])
    add(result, args.check, status, args.intent, args.target, output=text if status != "pass" else "",
        detail=f"step outcome: {args.outcome}")
    write(result, args.out)
    print(f"{args.check}: {status}")
