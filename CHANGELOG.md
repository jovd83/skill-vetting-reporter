# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[2.1.0]: https://github.com/jovd83/skill-vetting-reporter/releases/tag/v2.1.0
[2.0.0]: https://github.com/jovd83/skill-vetting-reporter/releases/tag/v2.0.0
[1.0.0]: https://github.com/jovd83/skill-vetting-reporter/releases/tag/v1.0.0
