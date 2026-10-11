# Alignment Audit (Rules 85-100 / 16 items) — model-origin-ledger v0.1.1

| # | Check | Status | Evidence |
|---|-------|--------|----------|
| 1 | Safety/Ethics section | PASS | Supply-chain security domain: README "Limits & Second-order Effects" is the ethics/boundary section — states openly that recomputation is integrity-not-authentication (re-signed-tail problem), license tiers are triage not legal advice, and the tool is verify-side only (no scanning of third-party systems) |
| 2 | Privacy/dezero | PASS | No secrets/tokens/real names; only contact line uses hcac4735@agent.qq.com; grep `(sk-\|ghp_\|api[_-]?key\s*=\s*['"][A-Za-z0-9])` → 0 hits |
| 3 | Copyright boundary | PASS | ModelBOM/pip-licenses/MLflow/in-toto comparisons are structural restatements (generator-vs-verify framing), no >50-char copied text; MIT LICENSE present, "zhengming contributors" |
| 4 | Fact-check annotation | PASS | 0.3 s / 500-record verify and ~45-60 s suite marked [Measured] with repro `python self_test.py` (C02 fixture); ModelBOM 0★ observation dated as of 2026-10-11 |
| 5 | Confidence grading | PASS | Opener [High ≥80%]; assumptions 2 and 3 [Medium]; ≥2 explicit labels in opener + [Core Assumptions] |
| 6 | PLAN B built-in | PASS | "Minimal Fallback (PLAN B)": sha256sum seal + `sha256sum -c` + git log, zero Python needed |
| 7 | Timeout preset | PASS | Quickstart states "~3 min" with per-step ≈1 s markers and ≈40-60 s for the full self-test |
| 8 | Rule-conflict arbitration | PASS | "Design Trade-offs" opens with priority: tamper-evidence > append-only discipline > audit expressiveness > convenience |
| 9 | Version changelog | PASS | CHANGELOG.md v0.1.0 + v0.1.1; v0.1.1 lists the `note`-field fix, normalization change, and test delta |
| 10 | Exemption instruction | N/A | Session-level rule; static repo content not applicable |
| 11 | External-knowledge cutoff | PASS | License-classifier contents and ModelBOM star observation dated "as of 2026-10-11"; no other vendor time-sensitive claims |
| 12 | Assumption explicitness | PASS | "[Core Assumptions]" section with 5 items |
| 13 | Logic-check trio | PASS | self_test.py tiers: [A] functional (20), [B] exception paths (12), [C] edges (10: unicode/500-record/5000-char/CRLF/blank-lines/seq-start); [R2] round-2 block (12 incl. threat-model pins). Final: `python self_test.py` → `SUMMARY: PASS 55/55` |
| 14 | Socratic question | PASS | FAQ "When NOT to use this tool?" with 4 anti-use-cases (third-party-verifiable provenance, dependency discovery, telemetry-frequency, signature-mandated regimes) |
| 15 | Pareto improvement | PASS | v0.1.1: tests 43→55 (+28% ≥20% gate) + 2 correctness fixes (note-field rejection blocked all multi-record appends; sha normalization) + threat-model documentation; re-run green |
| 16 | Ultimate fallback (≤60-word opener) | PASS | First paragraph = 58 words, contains what/who-needs-it judgment sentence |

Second-order effects (rule 16 bonus): PASS — "Limits & Second-order Effects" lists ledger theater, append chill, unknown-license mislabeling, plus the re-signed-tail authentication gap.

Scan evidence: `grep -rEn "(sk-|ghp_|api[_-]?key\s*=\s*['\"][A-Za-z0-9])" .` → 0 hits; `grep -rn "hcac4735@agent.qq.com" README.md` → 1 hit.
