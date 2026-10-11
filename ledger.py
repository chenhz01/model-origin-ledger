#!/usr/bin/env python3
"""model-origin-ledger: append-only provenance ledger for models and datasets.

Each record binds an artifact (name + sha256) to its upstream origin, license,
and UTC timestamp, and is chained by hash: every record's hash covers the
previous record's hash, so any edit, deletion, or reordering is detectable by
recomputation. A license classifier flags permissive / weak-copyleft /
strong-copyleft conflicts across the chain.

Verify-side tool: it audits what someone *claims* they used. It is not an
SBOM scanner that discovers dependencies for you.

Pure standard library. Python >= 3.8.
"""

import argparse
import hashlib
import json
import os
import sys
import tempfile
from datetime import datetime, timezone

VERSION = "0.1.1"

GENESIS_PREV = "0" * 64
KINDS = ("model", "dataset", "other")
REQUIRED_FIELDS = ("seq", "ts", "kind", "name", "sha256", "origin", "license",
                   "note", "prev_hash", "hash")

PERMISSIVE = {"mit", "bsd-2-clause", "bsd-3-clause", "apache-2.0", "isc",
              "zlib", "unlicense", "cc0-1.0", "bsl-1.0"}
WEAK_COPYLEFT = {"lgpl-2.1-only", "lgpl-2.1-or-later", "lgpl-3.0-only",
                 "lgpl-3.0-or-later", "mpl-2.0", "epl-2.0"}
STRONG_COPYLEFT = {"gpl-2.0-only", "gpl-2.0-or-later", "gpl-3.0-only",
                   "gpl-3.0-or-later", "agpl-3.0-only", "agpl-3.0-or-later"}

ALIASES = {
    "mit license": "mit",
    "apache 2.0": "apache-2.0",
    "apache license 2.0": "apache-2.0",
    "apache2": "apache-2.0",
    "bsd 2-clause": "bsd-2-clause",
    "bsd 3-clause": "bsd-3-clause",
    "gplv2": "gpl-2.0-only",
    "gplv3": "gpl-3.0-only",
    "gpl-2.0": "gpl-2.0-only",
    "gpl-3.0": "gpl-3.0-only",
    "agpl-3.0": "agpl-3.0-only",
    "lgpl-2.1": "lgpl-2.1-only",
    "lgpl-3.0": "lgpl-3.0-only",
    "cc-by-4.0": "cc-by-4.0",
}


def classify_license(license_str):
    """'GPL-3.0-only' -> 'strong-copyleft'; unknown -> 'unknown'."""
    norm = (license_str or "").strip().lower()
    norm = ALIASES.get(norm, norm)
    if norm in PERMISSIVE:
        return "permissive"
    if norm in WEAK_COPYLEFT:
        return "weak-copyleft"
    if norm in STRONG_COPYLEFT:
        return "strong-copyleft"
    return "unknown"


def canonical(rec):
    """Deterministic serialization of the record minus its own hash."""
    body = {k: rec[k] for k in rec if k != "hash"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def record_hash(prev_hash, rec_without_hash):
    return hashlib.sha256((prev_hash + canonical(rec_without_hash)).encode("utf-8")).hexdigest()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_ledger(path):
    """Parse JSONL -> (records, errors). Blank lines skipped, CRLF tolerated."""
    records, errors = [], []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for lineno, raw in enumerate(fh, 1):
                line = raw.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError as exc:
                    errors.append("line %d: not valid JSON: %s" % (lineno, exc))
                    continue
                if not isinstance(rec, dict):
                    errors.append("line %d: record is not an object" % lineno)
                    continue
                records.append(rec)
    except OSError as exc:
        errors.append("cannot read ledger: %s" % exc)
    return records, errors


def write_ledger(path, records):
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(path)) or ".",
                               suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            for rec in records:
                fh.write(json.dumps(rec, sort_keys=True, ensure_ascii=False) + "\n")
        os.replace(tmp, path)  # atomic on POSIX and Windows same-volume
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def check_chain(records):
    """Recompute the hash chain -> (errors, warnings). First error stops? No:
    collect all errors with their seq so tampering reports are actionable."""
    errors, warnings = [], []
    expected_prev = GENESIS_PREV
    seen_hashes = {}

    for i, rec in enumerate(records, 1):
        where = "seq %d" % i
        missing = [f for f in REQUIRED_FIELDS if f not in rec]
        if missing:
            errors.append("%s: missing field(s) %s" % (where, ", ".join(missing)))
            break
        extra = [k for k in rec if k not in REQUIRED_FIELDS]
        if extra:
            errors.append("%s: unknown field(s) %s (strict ledger)" % (where, ", ".join(extra)))
            break
        if not isinstance(rec["seq"], int) or rec["seq"] != i:
            errors.append("%s: seq is %r, expected %d" % (where, rec["seq"], i))
            break
        if rec["prev_hash"] != expected_prev:
            errors.append("%s: prev_hash mismatch (expected %s..., got %s...)"
                          % (where, expected_prev[:12], str(rec["prev_hash"])[:12]))
            break
        if not (isinstance(rec["hash"], str) and len(rec["hash"]) == 64
                and all(c in "0123456789abcdef" for c in rec["hash"])):
            errors.append("%s: hash field is not a sha256 hex digest" % where)
            break
        computed = record_hash(rec["prev_hash"], rec)
        if computed != rec["hash"]:
            errors.append("%s: hash mismatch — record content was altered "
                          "(stored %s..., computed %s...)"
                          % (where, rec["hash"][:12], computed[:12]))
            break
        if not (isinstance(rec["sha256"], str) and len(rec["sha256"]) == 64
                and all(c in "0123456789abcdef" for c in rec["sha256"])):
            warnings.append("%s: artifact sha256 is not a 64-hex digest" % where)
        if rec["sha256"] in seen_hashes:
            warnings.append("%s: duplicate artifact sha256 (also at seq %d)"
                            % (where, seen_hashes[rec["sha256"]]))
        else:
            seen_hashes[rec["sha256"]] = i
        if i > 1 and str(rec["ts"]) < str(records[i - 2]["ts"]):
            warnings.append("%s: timestamp goes backwards (ledger only requires append-order)"
                            % where)
        expected_prev = rec["hash"]

    return errors, warnings


def license_audit(records, project_license):
    """Return list of findings dicts: level (CONFLICT/NOTE/WARN/OK), seq, detail."""
    project_tier = classify_license(project_license)
    findings = []
    if project_tier == "unknown":
        findings.append({"level": "WARN", "seq": 0,
                         "detail": "project license %r not recognized" % project_license})
    for i, rec in enumerate(records, 1):
        tier = classify_license(rec.get("license", ""))
        label = "%s (seq %d, license %r)" % (rec.get("name", "?"), i, rec.get("license", "?"))
        if tier == "unknown":
            findings.append({"level": "WARN", "seq": i,
                             "detail": "%s: unknown license — manual review required" % label})
        elif tier == "strong-copyleft" and project_tier == "permissive":
            findings.append({"level": "CONFLICT", "seq": i,
                             "detail": "%s: strong copyleft inside permissive project "
                                       "— redistribution obligations likely incompatible" % label})
        elif tier == "weak-copyleft" and project_tier == "permissive":
            findings.append({"level": "NOTE", "seq": i,
                             "detail": "%s: weak copyleft — file-level obligations, "
                                       "usually compatible, verify boundaries" % label})
        else:
            findings.append({"level": "OK", "seq": i,
                             "detail": "%s: %s under %s project — no flag" % (
                                 label, tier, project_tier)})
    return findings


# ------------------------------------------------------------------------- CLI
def cmd_init(args):
    if os.path.exists(args.ledger) and not args.force:
        print("ledger already exists: %s (use --force to reset)" % args.ledger, file=sys.stderr)
        return 2
    write_ledger(args.ledger, [])
    print("initialized empty ledger: %s" % args.ledger)
    return 0


def cmd_append(args):
    if not os.path.exists(args.ledger):
        print("ledger not found: %s (run init first)" % args.ledger, file=sys.stderr)
        return 2
    records, errors = read_ledger(args.ledger)
    if errors:
        for e in errors:
            print("ledger error: %s" % e, file=sys.stderr)
        return 2
    chain_errors, _ = check_chain(records)
    if chain_errors:
        print("refusing to append to a ledger that fails verification:", file=sys.stderr)
        for e in chain_errors:
            print("  %s" % e, file=sys.stderr)
        return 1

    if args.file:
        if not os.path.isfile(args.file):
            print("artifact file not found: %s" % args.file, file=sys.stderr)
            return 2
        sha = sha256_file(args.file)
    elif args.sha256:
        sha = args.sha256.strip().lower()
        if len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
            print("--sha256 must be a 64-char hex digest", file=sys.stderr)
            return 2
    else:
        print("provide --file or --sha256", file=sys.stderr)
        return 2

    if not args.name:
        print("--name is required", file=sys.stderr)
        return 2
    if args.kind not in KINDS:
        print("--kind must be one of %s" % ", ".join(KINDS), file=sys.stderr)
        return 2

    prev = records[-1]["hash"] if records else GENESIS_PREV
    rec = {
        "seq": len(records) + 1,
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "kind": args.kind,
        "name": args.name,
        "sha256": sha,
        "origin": args.origin or "none",
        "license": args.license or "unknown",
        "note": args.note or "",
        "prev_hash": prev,
    }
    rec["hash"] = record_hash(prev, rec)
    records.append(rec)
    write_ledger(args.ledger, records)
    print("appended seq %d: %s (%s..., license %s)"
          % (rec["seq"], rec["name"], rec["sha256"][:12], rec["license"]))
    return 0


def cmd_verify(args):
    records, errors = read_ledger(args.ledger)
    for e in errors:
        print("ERROR: %s" % e)
    chain_errors, warnings = check_chain(records)
    for e in chain_errors:
        print("TAMPER: %s" % e)
    for w in warnings:
        print("WARN: %s" % w)
    if errors or chain_errors:
        return 1
    print("OK: %d records, hash chain intact" % len(records))
    return 0


def cmd_license_check(args):
    records, errors = read_ledger(args.ledger)
    if errors:
        for e in errors:
            print("ERROR: %s" % e, file=sys.stderr)
        return 2
    findings = license_audit(records, args.project_license)
    has_conflict = False
    for f in findings:
        print("%s: %s" % (f["level"], f["detail"]))
        if f["level"] == "CONFLICT":
            has_conflict = True
    if not findings:
        print("OK: no dependency records to audit")
    return 1 if has_conflict else 0


def cmd_show(args):
    records, errors = read_ledger(args.ledger)
    for e in errors:
        print("ERROR: %s" % e, file=sys.stderr)
    for rec in records:
        print("%3d  %-22s %-7s %-16s %s %s"
              % (rec.get("seq", -1), rec.get("name", "?"), rec.get("kind", "?"),
                 rec.get("license", "?"), rec.get("sha256", "?")[:12],
                 ("<- " + rec["origin"]) if rec.get("origin", "none") != "none" else ""))
    return 1 if errors else 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="origin-ledger",
        description="Append-only, hash-chained provenance ledger for AI models and "
                    "datasets, with license-tier conflict auditing.")
    parser.add_argument("--version", action="version", version="model-origin-ledger " + VERSION)
    sub = parser.add_subparsers(dest="cmd")

    p_init = sub.add_parser("init", help="create an empty ledger")
    p_init.add_argument("--ledger", default="ORIGIN_LEDGER.jsonl")
    p_init.add_argument("--force", action="store_true")

    p_app = sub.add_parser("append", help="append an artifact record")
    p_app.add_argument("--ledger", default="ORIGIN_LEDGER.jsonl")
    p_app.add_argument("--name", required=True)
    p_app.add_argument("--kind", default="model", choices=KINDS)
    p_app.add_argument("--file", help="hash this file (sha256)")
    p_app.add_argument("--sha256", help="or supply the digest directly")
    p_app.add_argument("--origin", default="none",
                       help="upstream source: URL or parent artifact hash")
    p_app.add_argument("--license", default="unknown")
    p_app.add_argument("--note", default="")

    p_ver = sub.add_parser("verify", help="recompute the hash chain")
    p_ver.add_argument("--ledger", default="ORIGIN_LEDGER.jsonl")

    p_lic = sub.add_parser("license-check", help="license-tier conflict audit")
    p_lic.add_argument("--ledger", default="ORIGIN_LEDGER.jsonl")
    p_lic.add_argument("--project-license", required=True)

    p_show = sub.add_parser("show", help="print the ledger")
    p_show.add_argument("--ledger", default="ORIGIN_LEDGER.jsonl")

    args = parser.parse_args(argv)
    if args.cmd is None:
        parser.print_help(sys.stderr)
        return 2
    return {"init": cmd_init, "append": cmd_append, "verify": cmd_verify,
            "license-check": cmd_license_check, "show": cmd_show}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
