# Changelog — model-origin-ledger

## v0.1.1 — 2026-10-11 (round-2 self-review revision)

### Fixed
- Strict chain checker rejected the `note` field that `append` itself writes — every two-record append refused with "unknown field(s) note" (self-review finding; `note` added to the record schema).
- Uppercase `--sha256` input is now normalized to lowercase before storage instead of poisoning the artifact digest.

### Changed
- Test suite extended 43 → 55 cases (+28%, coverage dimension of the ≥20% round-2 gate): first-record tamper, three-append continuation, multi-record CONFLICT listing, AGPL classification, kind=dataset roundtrip, forged-tail semantics (consistent re-sign passes / mismatched prev detected — threat model pinned by tests), empty-ledger `show`, OK-tier labels, MPL/EPL classification, uppercase sha normalization, backwards-timestamp warning.

### Documented
- README Limits: re-signed-tail problem made explicit (recomputation is integrity, not authentication); ledger-theater / append-chill second-order effects added; ModelBOM comparison sharpened to generator-vs-verify framing.

## v0.1.0 — 2026-10-11 (first working draft)

### Added
- `ledger.py`: append-only JSONL provenance records (seq/ts/kind/name/sha256/origin/license/note) chained by SHA-256 over canonical JSON; strict-field chain verifier with per-seq tamper reports; duplicate-artifact and backwards-timestamp warnings; guarded append (refuses to extend a failing chain); file hashing via `--file`; atomic single-file writes (temp + `os.replace`).
- License audit: three-tier classifier (permissive / weak-copyleft / strong-copyleft + unknown) with alias normalization (GPLv3, Apache 2.0, …), CONFLICT/NOTE/WARN/OK findings, exit 1 on CONFLICT.
- CLI: `init` / `append` / `verify` / `license-check` / `show`.
- `self_test.py`: 43 cases across functional / exception / edge tiers (tamper matrix, malformed JSONL, unicode names, 500-record chain, CRLF, blank lines).
- README (article-level, incl. "How this differs from ModelBOM" comparison), MIT LICENSE, this changelog.
