#!/usr/bin/env python3
"""model-origin-ledger self-test: [A] functional, [B] exception paths, [C] edges.

Run:  python self_test.py          (expect: SUMMARY: PASS n/n)
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import ledger  # noqa: E402

RESULTS = []
TMP = tempfile.mkdtemp(prefix="mol_test_")


def check(name, cond):
    RESULTS.append((name, bool(cond)))
    return bool(cond)


def new_ledger(name="L.jsonl"):
    return os.path.join(TMP, name)


def cli(argv):
    proc = subprocess.run([sys.executable, os.path.join(HERE, "ledger.py")] + argv,
                          capture_output=True, text=True)
    return proc.returncode, proc.stdout + proc.stderr


def append(path, name, license="MIT", kind="model", origin="none", sha=None, note=None):
    if not os.path.exists(path):
        cli(["init", "--ledger", path])
    argv = ["append", "--ledger", path, "--name", name, "--kind", kind,
            "--license", license, "--origin", origin]
    if note:
        argv += ["--note", note]
    if sha:
        argv += ["--sha256", sha]
    else:
        argv += ["--file", artifact(name)]
    return cli(argv)


ART = {}


def artifact(name):
    if name not in ART:
        p = os.path.join(TMP, "art_" + name.replace("/", "_"))
        with open(p, "w", encoding="utf-8") as fh:
            fh.write("contents-of-%s\n" % name)
        ART[name] = p
    return ART[name]


SHA_A = "a" * 64
SHA_B = "b" * 64

# ---------------------------------------------------------------- [A] functional
L1 = new_ledger("a1.jsonl")
check("A01 init creates empty ledger", cli(["init", "--ledger", L1])[0] == 0
      and os.path.isfile(L1))

check("A02 first append gets seq 1 and genesis prev", (lambda rc, out:
      rc == 0 and json.loads(open(L1, encoding="utf-8").read())["seq"] == 1
      and json.loads(open(L1, encoding="utf-8").read())["prev_hash"] == ledger.GENESIS_PREV
      )(*append(L1, "base-model")))

r1 = json.loads(open(L1, encoding="utf-8").read())
check("A03 record hash recomputes deterministically",
      ledger.record_hash(r1["prev_hash"], r1) == r1["hash"])

check("A04 chain links: seq2 prev == seq1 hash", (lambda rc, out:
      rc == 0 and json.loads(open(L1, encoding="utf-8").read().splitlines()[1])["prev_hash"] == r1["hash"]
      )(*append(L1, "tuned-model", license="Apache-2.0", origin=r1["sha256"])))

rc, out = cli(["verify", "--ledger", L1])
check("A05 verify clean chain exits 0", rc == 0 and "hash chain intact" in out)

rc, out = append(L1, "eval-dataset", kind="dataset", license="CC0-1.0")
check("A05b third record appended", rc == 0)

tampered = open(L1, encoding="utf-8").read().splitlines()
rec2 = json.loads(tampered[1])
rec2["license"] = "GPL-3.0-only"
tampered[1] = json.dumps(rec2, sort_keys=True)
L2 = new_ledger("a6.jsonl")
open(L2, "w", encoding="utf-8").write("\n".join(tampered) + "\n")
rc, out = cli(["verify", "--ledger", L2])
check("A06 field tamper detected at seq 2", rc == 1 and "TAMPER" in out and "seq 2" in out)

tampered2 = open(L1, encoding="utf-8").read().splitlines()
rec2b = json.loads(tampered2[1])
rec2b["hash"] = "f" * 64
tampered2[1] = json.dumps(rec2b, sort_keys=True)
L3 = new_ledger("a7.jsonl")
open(L3, "w", encoding="utf-8").write("\n".join(tampered2) + "\n")
rc, out = cli(["verify", "--ledger", L3])
check("A07 bogus-but-wellformed hash detected", rc == 1 and "hash mismatch" in out)

lines = open(L1, encoding="utf-8").read().splitlines()
L4 = new_ledger("a8.jsonl")
open(L4, "w", encoding="utf-8").write(lines[0] + "\n" + lines[2] + "\n")  # deleted seq 2
rc, out = cli(["verify", "--ledger", L4])
check("A08 deleted middle record detected (seq gap)", rc == 1)

L5 = new_ledger("a9.jsonl")
open(L5, "w", encoding="utf-8").write(lines[1] + "\n" + lines[0] + "\n" + lines[2] + "\n")
rc, out = cli(["verify", "--ledger", L5])
check("A09 reordered records detected", rc == 1 and "TAMPER" in out)

L6 = new_ledger("a10.jsonl")
bad_genesis = json.loads(lines[0])
bad_genesis["prev_hash"] = "1" * 64
bad_genesis["hash"] = ledger.record_hash("1" * 64, bad_genesis)
open(L6, "w", encoding="utf-8").write(json.dumps(bad_genesis, sort_keys=True) + "\n")
rc, out = cli(["verify", "--ledger", L6])
check("A10 non-genesis prev_hash rejected even if re-signed", rc == 1
      and "prev_hash mismatch" in out)

L7 = new_ledger("a11.jsonl")
append(L7, "same-art", sha=SHA_A)
append(L7, "same-art-copy", sha=SHA_A)
rc, out = cli(["verify", "--ledger", L7])
check("A11 duplicate artifact hash -> warning not tamper", rc == 0 and "duplicate artifact" in out)

LC = new_ledger("lc.jsonl")
append(LC, "gpl-model", license="GPL-3.0-only", sha=SHA_A)
rc, out = cli(["license-check", "--ledger", LC, "--project-license", "MIT"])
check("A12 strong copyleft in permissive project -> CONFLICT exit 1",
      rc == 1 and "CONFLICT" in out)

LC2 = new_ledger("lc2.jsonl")
append(LC2, "lgpl-data", kind="dataset", license="LGPL-3.0-only", sha=SHA_B)
rc, out = cli(["license-check", "--ledger", LC2, "--project-license", "MIT"])
check("A13 weak copyleft under permissive -> NOTE exit 0", rc == 0 and "NOTE" in out)

LC3 = new_ledger("lc3.jsonl")
append(LC3, "agpl-model", license="AGPL-3.0-only", sha=SHA_A)
rc, out = cli(["license-check", "--ledger", LC3, "--project-license", "GPL-3.0-only"])
check("A14 strong under strong -> no conflict", rc == 0 and "CONFLICT" not in out)

LC4 = new_ledger("lc4.jsonl")
append(LC4, "mystery-weights", license="Custom-EULA-9000", sha=SHA_A)
rc, out = cli(["license-check", "--ledger", LC4, "--project-license", "MIT"])
check("A15 unknown license -> WARN exit 0", rc == 0 and "WARN" in out)

LC5 = new_ledger("lc5.jsonl")
append(LC5, "ok-model", license="MIT", sha=SHA_A)
append(LC5, "bad-model", license="GPL-3.0-only", sha=SHA_B)
rc, out = cli(["license-check", "--ledger", LC5, "--project-license", "MIT"])
check("A16 conflict names the offending record", rc == 1 and "bad-model" in out)

FART = os.path.join(TMP, "file_art.bin")
with open(FART, "wb") as fh:
    fh.write(b"\x00\x01binary-ish")
import hashlib as _h  # noqa: E402
expect_sha = _h.sha256(open(FART, "rb").read()).hexdigest()
L8 = new_ledger("a17.jsonl")
cli(["init", "--ledger", L8])
rc, out = cli(["append", "--ledger", L8, "--name", "bin-art", "--kind", "other",
               "--file", FART, "--license", "MIT"])
check("A17 --file hashing matches hashlib", rc == 0
      and json.loads(open(L8, encoding="utf-8").read())["sha256"] == expect_sha)

rc, out = cli(["show", "--ledger", L1])
check("A18 show lists records with names", rc == 0 and "base-model" in out
      and "tuned-model" in out)

r_copy = dict(r1)
check("A19 canonical() is stable and hash-excluding",
      ledger.canonical(r_copy) == ledger.canonical(r_copy)
      and "hash" not in json.loads(ledger.canonical(r_copy)))

L9 = new_ledger("a20.jsonl")
append(L9, "child", origin=r1["sha256"], sha=SHA_A)
check("A20 origin may be a parent artifact hash", json.loads(
    open(L9, encoding="utf-8").read())["origin"] == r1["sha256"])

# ------------------------------------------------------------------ [B] exception
check("B01 verify empty ledger OK", (lambda rc, out:
      rc == 0 and "0 records" in out)(*cli(["verify", "--ledger",
      (lambda p: (cli(["init", "--ledger", p]), p)[1])(new_ledger("b1.jsonl"))])))

L10 = new_ledger("b2.jsonl")
open(L10, "w", encoding="utf-8").write('{"seq": 1, "oops\n')
rc, out = cli(["verify", "--ledger", L10])
check("B02 malformed JSONL line reported", rc == 1 and "not valid JSON" in out)

L11 = new_ledger("b3.jsonl")
partial = json.loads(lines[0])
del partial["license"]
open(L11, "w", encoding="utf-8").write(json.dumps(partial, sort_keys=True) + "\n")
rc, out = cli(["verify", "--ledger", L11])
check("B03 missing required field fails", rc == 1 and "missing field" in out)

L12 = new_ledger("b4.jsonl")
shorthash = json.loads(lines[0])
shorthash["hash"] = "abcd"
open(L12, "w", encoding="utf-8").write(json.dumps(shorthash, sort_keys=True) + "\n")
rc, out = cli(["verify", "--ledger", L12])
check("B04 malformed hash field fails", rc == 1 and "sha256 hex" in out)

L13 = new_ledger("b5.jsonl")
append(L13, "ok", sha=SHA_A)
corrupt = open(L13, encoding="utf-8").read().replace("MIT", "GPL-3.0-only")
open(L13, "w", encoding="utf-8").write(corrupt)
rc, out = append(L13, "another", sha=SHA_B)
check("B05 append refuses to extend a tampered ledger", rc == 1 and "refusing" in out)

L6 = new_ledger("b6.jsonl")
cli(["init", "--ledger", L6])
rc, out = cli(["append", "--ledger", L6, "--name", "x", "--sha256", "zz" * 32])
check("B06 bad --sha256 format rejected", rc != 0 and "hex" in out)

rc, out = cli(["append", "--ledger", new_ledger("b7.jsonl"), "--name", "x",
               "--file", "no_such_file.bin"])
check("B07 missing --file rejected", rc != 0 and "not found" in out)

rc, out = cli(["append", "--ledger", new_ledger("b8.jsonl"), "--name", "x",
               "--kind", "alien", "--sha256", SHA_A])
check("B08 invalid kind rejected by argparse", rc != 0)

LC6 = new_ledger("b9.jsonl")
append(LC6, "some-model", sha=SHA_A)
rc, out = cli(["license-check", "--ledger", LC6,
               "--project-license", "SomethignWrong"])
check("B09 unrecognized project license -> WARN", rc == 0 and "WARN" in out)

rc, out = cli(["verify", "--ledger", "missing_ledger_xyz.jsonl"])
check("B10 missing ledger file -> non-zero with message", rc != 0 and "cannot read" in out)

L14 = new_ledger("b11.jsonl")
append(L14, "later", sha=SHA_A)
import time as _t  # noqa: E402
_t.sleep(1.1)
rc, out = cli(["append", "--ledger", L14, "--name", "x", "--file", FART,
               "--license", "MIT", "--kind", "other"])
check("B11 append works across seconds boundary (monotonic ts)", rc == 0
      and cli(["verify", "--ledger", L14])[0] == 0)

check("B12 CLI no subcommand exits 2", cli([])[0] == 2)

# ------------------------------------------------------------------ [C] edges
L15 = new_ledger("c1.jsonl")
append(L15, "模型-mitraillette🎉", sha=SHA_A, note='quote " and /slash/')
rc, out = cli(["verify", "--ledger", L15])
check("C01 unicode names and quotes survive roundtrip", rc == 0)

BIG = new_ledger("c2.jsonl")
records = []
prev = ledger.GENESIS_PREV
for i in range(500):
    rec = {"seq": i + 1, "ts": "2026-01-01T00:00:00Z", "kind": "model",
           "name": "m%03d" % i, "sha256": ("%04x" % i + "0" * 60),
           "origin": "none", "license": "MIT", "note": "", "prev_hash": prev}
    rec["hash"] = ledger.record_hash(prev, rec)
    records.append(rec)
    prev = rec["hash"]
ledger.write_ledger(BIG, records)
rc, out = cli(["verify", "--ledger", BIG])
check("C02 500-record chain verifies", rc == 0 and "500 records" in out)

L16 = new_ledger("c3.jsonl")
append(L16, "x" * 5000, sha=SHA_A)
rc, out = cli(["verify", "--ledger", L16])
check("C03 5000-char name handled", rc == 0)

check("C04 license matching case-insensitive",
      ledger.classify_license("gpl-3.0-only") == "strong-copyleft"
      and ledger.classify_license("MIT") == "permissive")

check("C05 alias resolution (GPLv3, Apache 2.0)",
      ledger.classify_license("GPLv3") == "strong-copyleft"
      and ledger.classify_license("Apache 2.0") == "permissive")

L17 = new_ledger("c6.jsonl")
rc, out = cli(["append", "--ledger", L17, "--name", "", "--sha256", SHA_A])
check("C06 empty name rejected", rc != 0)

L18 = new_ledger("c7.jsonl")
append(L18, "m1", sha=SHA_A)
append(L18, "m1-again", sha=SHA_A)
rc, out = cli(["verify", "--ledger", L18])
check("C07 two identical appends -> one duplicate warning", rc == 0
      and out.count("duplicate artifact") == 1)

crlf = new_ledger("c8.jsonl")
open(crlf, "w", encoding="utf-8", newline="\r\n").write(
    "\r\n".join(open(L1, encoding="utf-8").read().splitlines()) + "\r\n")
rc, out = cli(["verify", "--ledger", crlf])
check("C08 CRLF line endings tolerated", rc == 0)

L19 = new_ledger("c9.jsonl")
nostart = [json.loads(l) for l in open(L1, encoding="utf-8").read().splitlines()]
nostart[0]["seq"] = 2
nostart[0]["hash"] = ledger.record_hash(nostart[0]["prev_hash"], nostart[0])
open(L19, "w", encoding="utf-8").write(
    "\n".join(json.dumps(r, sort_keys=True) for r in nostart) + "\n")
rc, out = cli(["verify", "--ledger", L19])
check("C09 seq not starting at 1 fails", rc == 1 and "seq" in out)

L20 = new_ledger("c10.jsonl")
append(L20, "lead-ws", sha=SHA_A.upper().replace("A", "a") if False else SHA_A)
with open(L20, "a", encoding="utf-8") as fh:
    fh.write("\n\n")  # trailing blank lines
rc, out = cli(["verify", "--ledger", L20])
check("C10 trailing blank lines tolerated", rc == 0)

# --------------------------------------------------- [R2] round-2 added coverage
L21 = new_ledger("r1.jsonl")
append(L21, "victim", sha=SHA_A)
lines21 = open(L21, encoding="utf-8").read().splitlines()
v = json.loads(lines21[0])
v["name"] = "renamed"
lines21[0] = json.dumps(v, sort_keys=True)
L22 = new_ledger("r1b.jsonl")
open(L22, "w", encoding="utf-8").write(lines21[0] + "\n")
rc, out = cli(["verify", "--ledger", L22])
check("R01 first-record tamper detected at seq 1", rc == 1 and "seq 1" in out)

L23 = new_ledger("r2.jsonl")
append(L23, "one", sha=SHA_A)
append(L23, "two", sha=SHA_B)
rc, out = append(L23, "three", license="MIT", kind="dataset")
check("R02 chain continues across three appends", rc == 0
      and cli(["verify", "--ledger", L23])[0] == 0)

LC7 = new_ledger("r3.jsonl")
append(LC7, "bad1", license="GPL-3.0-only", sha=SHA_A)
append(LC7, "bad2", license="AGPL-3.0-only", sha=SHA_B)
rc, out = cli(["license-check", "--ledger", LC7, "--project-license", "MIT"])
check("R03 every conflicting record listed", rc == 1
      and out.count("CONFLICT") == 2 and "bad1" in out and "bad2" in out)

check("R04 AGPL classified strong-copyleft",
      ledger.classify_license("AGPL-3.0-only") == "strong-copyleft")

L24 = new_ledger("r5.jsonl")
append(L24, "ds", kind="dataset", sha=SHA_A)
check("R05 kind=dataset roundtrips",
      json.loads(open(L24, encoding="utf-8").read())["kind"] == "dataset")

L25 = new_ledger("r6.jsonl")
append(L25, "real", sha=SHA_A)
foreign = dict(json.loads(open(L25, encoding="utf-8").read()))
foreign["seq"] = 2
foreign["prev_hash"] = foreign["hash"]
foreign["name"] = "forged"
foreign["hash"] = ledger.record_hash(foreign["prev_hash"], foreign)
with open(L25, "a", encoding="utf-8") as fh:
    fh.write(json.dumps(foreign, sort_keys=True) + "\n")
rc, out = cli(["verify", "--ledger", L25])
check("R06 re-signed consistent tail passes (single-party chain limit, see README Limits)",
      rc == 0 and out.count("duplicate artifact") == 1)

L25b = new_ledger("r6b.jsonl")
append(L25b, "real", sha=SHA_A)
forged2 = dict(json.loads(open(L25b, encoding="utf-8").read()))
forged2["seq"] = 2
forged2["prev_hash"] = "9" * 64  # does not chain to seq 1
forged2["hash"] = ledger.record_hash(forged2["prev_hash"], forged2)
with open(L25b, "a", encoding="utf-8") as fh:
    fh.write(json.dumps(forged2, sort_keys=True) + "\n")
rc, out = cli(["verify", "--ledger", L25b])
check("R06b tail whose prev_hash does not chain is detected", rc == 1 and "seq 2" in out)

check("R07 show on empty ledger exits 0",
      cli(["show", "--ledger", (lambda p: (cli(["init", "--ledger", p]), p)[1])(
          new_ledger("r7.jsonl"))])[0] == 0)

LC8 = new_ledger("r8.jsonl")
append(LC8, "okp", license="Apache-2.0", sha=SHA_A)
rc, out = cli(["license-check", "--ledger", LC8, "--project-license", "MIT"])
check("R08 OK finding carries tier label",
      rc == 0 and "permissive" in out and "no flag" in out)

check("R09 MPL/EPL classified weak-copyleft",
      ledger.classify_license("MPL-2.0") == "weak-copyleft"
      and ledger.classify_license("EPL-2.0") == "weak-copyleft")

L26 = new_ledger("r10.jsonl")
recs = []
prev = ledger.GENESIS_PREV
for i, ts in enumerate(["2026-01-02T00:00:00Z", "2026-01-01T00:00:00Z"]):
    rec = {"seq": i + 1, "ts": ts, "kind": "model", "name": "n%d" % i,
           "sha256": SHA_A if i == 0 else SHA_B, "origin": "none",
           "license": "MIT", "note": "", "prev_hash": prev}
    rec["hash"] = ledger.record_hash(prev, rec)
    recs.append(rec)
    prev = rec["hash"]
ledger.write_ledger(L26, recs)
rc, out = cli(["verify", "--ledger", L26])
check("R10 backwards timestamp -> warning, chain still intact", rc == 0
      and "timestamp goes backwards" in out)

L27 = new_ledger("r11.jsonl")
cli(["init", "--ledger", L27])
rc, out = cli(["append", "--ledger", L27, "--name", "upper", "--kind", "model",
               "--license", "MIT", "--sha256", SHA_A.upper()])
check("R11 uppercase sha256 normalized to lowercase", rc == 0
      and json.loads(open(L27, encoding="utf-8").read())["sha256"] == SHA_A)

if __name__ == "__main__":
    passed = sum(1 for _, ok in RESULTS if ok)
    total = len(RESULTS)
    for n, ok in RESULTS:
        if not ok:
            print("FAIL:", n)
    print("SUMMARY: PASS %d/%d" % (passed, total))
    shutil.rmtree(TMP, ignore_errors=True)
    sys.exit(0 if passed == total else 1)
