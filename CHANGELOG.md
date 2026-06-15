# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

### Changed

### Fixed

### Removed

## [2.5.1] - 2026-06-15

### Fixed
- **Scanner-gate severity counts and recommendation for NVIDIA SkillSpector
  (and any scanner that reports per-finding severities instead of aggregate
  counts).** `run_scanners.py` previously only looked for aggregate count fields
  (`critical`/`high_count`/…), so SkillSpector's `issues[].severity` array was
  never tallied — the gate table showed **"none"** even on a `score=100.0`,
  `DO_NOT_INSTALL` result, which read like an inverted-scale bug. The
  recommendation lookup also did an unordered deep search that could return an
  arbitrary *per-finding* `severity` (e.g. "MEDIUM") instead of the overall
  verdict. Now the runner tallies severities from a findings/issues array when
  no aggregate counts are present, and resolves the recommendation from
  unambiguous verdict keys (`recommendation`/`verdict`/`max_severity`, e.g.
  SkillSpector's `risk_assessment.recommendation = "DO_NOT_INSTALL"`), falling
  back only to a *top-level* `severity` so per-finding severities can't pollute
  it. The score≥51→BLOCK threshold itself was already correct and is unchanged;
  affected BLOCKs were genuine, just under-reported in the table. Added a
  boolean guard so a `critical: true`-style flag is not miscounted as 1.

## [2.5.0] - 2026-06-15

### Added
- **Placeholder-value hint for hardcoded-secret findings.** When a "Hardcoded
  secret" finding's value looks like a placeholder (`change-this`/`change-me`,
  `your-...-key/token/secret/password-here`, `sample`/`dummy`/`placeholder`/
  `example`/`fake`/`redacted`/`todo`/etc., repeated `x`/`*`/`0`/`1` runs,
  `${...}`/`{{...}}`/`<...>`/`%...%` template syntax, or a hyphen/underscore-joined
  word phrase like `super-secret-key-change-this-in-production`), the report now
  marks it with `⚑ placeholder?` (HTML badge) / a `⚑ Looks like a placeholder
  value...` note (Markdown). The Metrics & risk score section adds a matching
  "N of M look like placeholder value(s); verify" note on the Hard credential
  hits line. This is a **hint only** — the finding is still listed, still counts
  toward the score, a hard-credential hit still forces "Decline", and the
  `☐ confirmed ☐ false positive ☐ documented-not-performed` reviewer checkbox is
  unchanged. New legend entries explain the marker in both report formats.

## [2.4.1] - 2026-06-12

### Changed
- Clarified the OWASP map legend for **`clear`** (HTML legend + Markdown §4
  footnote): it now states that `clear` means the category *was* checked and no
  known pattern matched — explicitly **not** "could not check" and **not** proof
  of safety (known-pattern scan only; ASI06–ASI10 need human judgement; scanner
  coverage gaps are shown in §0).

## [2.4.0] - 2026-06-12

### Added
- **HTML report: collapsible panes.** Every section is now a `<details>` pane with
  a chevron and can be expanded/collapsed independently.
- **HTML report: per-pane legends.** A `?` button next to the title of the Profile,
  scanner gate, Findings, OWASP, Metrics & risk score, and Suggested tier panes
  toggles a legend that defines the coded terms (gate verdicts and scanner
  statuses; finding severities; OWASP signal terms and finding categories like
  "clear" / External domains / Exfiltration channel; the score recommendations and
  metric penalties; Tier 0-3 / REJECT; author trust levels). Markdown output is
  unchanged.

## [2.3.1] - 2026-06-12

### Fixed
- Mojibake in the committed `examples/sample-report.md` and `sample-report.html`
  (em-dash, ☐, ⚠ rendered as `â€"`/`â˜`/`âš `). Caused by sanitizing the samples
  through a PowerShell `Get-Content`/`Set-Content` round-trip that decoded the
  UTF-8 output as cp1252; regenerated as clean UTF-8. The live report output was
  never affected (it is written directly by Python as UTF-8).

## [2.3.0] - 2026-06-12

### Added
- **Profile & summary section** in every report: skill category (from
  `dispatcher-category` or inferred), what-it-does, a synthesized 1-2 paragraph
  summary, and an **author** block with trust + credibility + "about", resolved
  against a new `references/trusted_authors.json` allowlist.
- **Two-phase model**: Phase 1 = live author lookup (the only online step; result
  passed in via `--profile profile.json`), Phase 2 = the offline static scan. The
  static scanner still never fetches.
- **Metrics & risk score section**: structural counts (subfolders, files,
  assets/references/scripts files, total + misplaced scripts) and security counts
  (dangerous, network/tool, soft- & hard-credential hits, writes-files declared)
  with a heuristic 0-100 score and a No-further-review / Further-review / Decline
  recommendation (misplaced −5/cap4, dangerous −8/cap8→Decline, network −2/cap12,
  soft-cred −5/cap4, hard-cred −40/any→Decline). **Additive** — never overrides the
  existing gate verdict or Tier 0-3.
- `vet_skill.py --profile <json>` to inject the Phase-1 lookup + narrative.

### Changed
- Frontmatter parser now flattens nested `metadata:` children (author, version,
  `dispatcher-*`) so they are visible to the report.

## [2.2.0] - 2026-06-11

### Added
- **HTML report output** via `vet_skill.py --format html` (or `both`), styled with
  the new `assets/report-template.html` shell that matches the skill-dispatcher
  wallboard's "warm paper" visual language (terracotta/olive/gold on paper, serif
  hero, accent-barred cards, severity badges). Markdown stays the default; the
  HTML renders from the same computed data, so the two never drift. Adds
  `examples/sample-report.html`.

## [2.1.0] - 2026-06-10

### Added
- OWASP coverage map (report §4) now has an **"Advice — what good looks like"**
  column with concrete per-ASI mitigation guidance, so the table recommends a fix
  rather than only posing a reviewer question.

## [2.0.0] - 2026-06-10

### Added
- **Mandatory open-source scanner gate** (`scripts/run_scanners.py`): detects and
  runs installed AgentSkill scanners — Cisco AI Defense skill-scanner, NVIDIA
  SkillSpector, Snyk Agent Scan, sentry/skill-scanner — and produces a single
  gate verdict (PASS / BLOCK / INCOMPLETE). Detect-and-run only; never
  auto-installs. Snyk via `uvx` is opt-in (`--allow-uvx`).
- **OWASP Top 10 for Agentic Applications (ASI01–ASI10) coverage map** in every
  report, with `references/owasp-top10-agent-skills.md` as the grounding doc.
- **Batch roll-up** (`scripts/vet_batch.py`): vets every skill under a directory
  and writes a risk-sorted `batch_summary.md` plus one full report per skill.
- **Scanner-failure retry, classified by cause**: transient failures
  (timeout/network/5xx) retry the same command with backoff (`--retries`);
  a strict-parser failure on a control character in the frontmatter (a stray TAB
  or a C1 control such as U+009D from a mangled em-dash) retries once against a
  normalized copy (`--no-normalize-retry` to disable), always labelled in §0.
- **Example fixture + sample report** (`examples/example-skill/`,
  `examples/sample-report.md`) demonstrating a dismissible false positive.
- `references/scanners.md` — per-tool install/run/trust notes.
- `vet_skill.py --scanners <json>` folds the gate verdict into report §0 and into
  the tier logic (a BLOCK forces reject/escalate; INCOMPLETE blocks Tier 1+).
- On-demand invocation patterns ("run the vetting on skill X", "vet skills X and
  Y", "scan everything in ~/.agents/skills").
- "Gotchas (how to read the results)" section in SKILL.md.
- Heuristic for YAML-illegal control characters in frontmatter, reported as a
  Metadata warning (quality + mild anti-analysis signal).
- Repository scaffolding: README, CHANGELOG, MIT LICENSE, and a
  `.github/workflows/validate.yml` validation workflow.

### Changed
- Report restructured: new §0 (scanner gate) and §4 (OWASP map); sections
  renumbered through §8 (sign-off). Tier reasoning is now gate-aware.
- Frontmatter parser now resolves YAML block scalars (`description: >`/`|`) to
  their real text instead of showing the indicator.
- A scanner that exits non-zero with no parseable output is recorded as `error`
  (not a clean run); Snyk with no `SNYK_TOKEN` is `skipped` rather than failed.
- Frontmatter: `license` changed to MIT; added `metadata.author` and
  `metadata.version`; description expanded for on-demand triggering.

## [1.0.0] - 2026-05-01

### Added
- Initial release: static heuristic scanner (`scripts/vet_skill.py`) producing a
  draft vetting report — file inventory, executable surface, findings by
  severity, red-flag checklist, suggested review tier (0–3), and reviewer
  sign-off sections. Static analysis only; never executes the reviewed skill.

[2.5.1]: https://github.com/jovd83/skill-vetting-reporter/releases/tag/v2.5.1
[2.5.0]: https://github.com/jovd83/skill-vetting-reporter/releases/tag/v2.5.0
[2.4.1]: https://github.com/jovd83/skill-vetting-reporter/releases/tag/v2.4.1
[2.4.0]: https://github.com/jovd83/skill-vetting-reporter/releases/tag/v2.4.0
[2.3.1]: https://github.com/jovd83/skill-vetting-reporter/releases/tag/v2.3.1
[2.3.0]: https://github.com/jovd83/skill-vetting-reporter/releases/tag/v2.3.0
[2.2.0]: https://github.com/jovd83/skill-vetting-reporter/releases/tag/v2.2.0
[2.1.0]: https://github.com/jovd83/skill-vetting-reporter/releases/tag/v2.1.0
[2.0.0]: https://github.com/jovd83/skill-vetting-reporter/releases/tag/v2.0.0
[1.0.0]: https://github.com/jovd83/skill-vetting-reporter/releases/tag/v1.0.0
