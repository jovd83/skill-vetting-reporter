# External scanner gate — tool reference

`scripts/run_scanners.py` detects and runs whichever of these four open-source /
free AgentSkill scanners are installed, then normalizes their output into a
single gate verdict (PASS / BLOCK / INCOMPLETE). It **never auto-installs**
anything. This file is the per-tool install/run/trust reference.

> Trust note that applies to all four: these are third-party tools. Running them
> executes *their* code against the target, not the target's code. Snyk in
> particular is fetched and run via `uvx` on each invocation, so it is opt-in.
> Vet new scanner tools with the same care you would any dependency before
> trusting their installer.

## Contents
- [How the gate decides](#how-the-gate-decides)
- [Cisco AI Defense skill-scanner](#cisco-ai-defense-skill-scanner)
- [NVIDIA SkillSpector](#nvidia-skillspector)
- [Snyk Agent Scan](#snyk-agent-scan)
- [sentry/skill-scanner (community)](#sentryskill-scanner-community)
- [Adding another scanner](#adding-another-scanner)

## How the gate decides

For each scanner the runner records `ran` / `missing` / `error`. From the ones
that ran:
- **BLOCK** if any scanner reports a critical/high finding, a risk score ≥ 51,
  or a "do not install" recommendation (parsed from JSON, or matched in raw
  output as a fallback). A BLOCK forces the report toward reject/escalate and
  exits the runner with code 2 (useful for CI).
- **PASS** if at least one scanner ran and none blocked.
- **INCOMPLETE** if zero scanners ran. This is *not* a pass — Tier 1+ approval
  requires at least one scanner, or a documented reviewer exception.

The runner is tolerant by design: scanner JSON schemas differ and evolve, so it
extracts severity counts / score / recommendation from common field names and
keeps a trimmed raw tail for the reviewer. If a tool changes its output format,
the gate degrades to raw-marker matching rather than breaking.

### Retry on failure

A scanner failure is classified before it is recorded, so the runner retries
only when a retry can actually help:

- **Recoverable parser failure** — a strict YAML loader (e.g. Cisco) chokes on a
  control character in the target's frontmatter: a stray TAB, or a C1 control
  like **U+009D** produced by a mangled em-dash. A plain retry is useless (the
  input is unchanged), so the runner re-runs **once against a temp copy whose
  frontmatter control characters are sanitized** (`TAB`→spaces, other illegal
  controls→space; body and other files byte-identical). The result is labelled
  `ran (retried)` with a "Retries" note, and `vet_skill.py` independently records
  the control character as a **Metadata warning** so the anomaly is never
  silently sanitized away. Disable with `--no-normalize-retry`.
- **Transient failure** — timeout, connection error, rate limit, 5xx: the same
  command is retried up to `--retries N` times (default 1) with a short backoff.
- **Anything else** — recorded as `error`; no retry.

Why label and record rather than silently fix: "breaks one scanner's parser but
not another" is itself a mild anti-analysis signal, and scanning a modified copy
is not the same as scanning the artifact that will be installed. The reviewer is
always told what was changed and why.

## Cisco AI Defense skill-scanner
- Repo: https://github.com/cisco-ai-defense/skill-scanner
- Install: `pip install cisco-ai-skill-scanner`
- Detected as: the `skill-scanner` binary on PATH.
- Run (what the gate uses): `skill-scanner scan <path> --format json`
- Enhanced (gate `--enhanced`): adds `--use-behavioral --use-llm --enable-meta`
  — signature + LLM semantic analysis + behavioural dataflow. The LLM engine may
  need API credentials; leave it off for a pure-static run.
- Exit codes: `0` = no HIGH/CRITICAL; non-zero = policy-violation findings.
- Strengths: ASI01 (prompt injection), ASI05 (behavioural dataflow). Documents
  that "no findings ≠ no risk".

## NVIDIA SkillSpector
- Repo: https://github.com/NVIDIA/SkillSpector
- Install: `git clone …/SkillSpector && cd SkillSpector && uv venv && make install`
- Detected as: the `skillspector` binary on PATH.
- Run: `skillspector scan <path> --format json`
- Coverage: 64 patterns across 16 categories — prompt injection, data
  exfiltration, privilege escalation, supply chain, excessive agency, output
  handling, system-prompt leakage, memory poisoning, tool misuse, rogue agent,
  trigger abuse, behavioural AST, taint tracking, YARA signatures, MCP least
  privilege, MCP tool poisoning.
- Risk score → recommendation: 0–20 LOW/SAFE, 21–50 MEDIUM/CAUTION, 51–80
  HIGH/DO NOT INSTALL, 81–100 CRITICAL/DO NOT INSTALL. The gate treats ≥ 51 as
  BLOCK.
- Strengths: broadest single-tool pattern coverage; explicit install recommendation.

## Snyk Agent Scan
- Repo: https://github.com/snyk/agent-scan · PyPI: https://pypi.org/project/snyk-agent-scan/
  · web Skill Inspector: https://labs.snyk.io/experiments/skill-scan/
- Run via uvx (opt-in): `uvx snyk-agent-scan@latest <path> --json`
- Detected as: a local `snyk-agent-scan` binary **or**, only when you pass
  `--allow-uvx`, via `uvx`. The opt-in exists because `uvx` fetches and runs
  remote code on every invocation.
- Auth: requires `SNYK_TOKEN` in the environment; without it the scan will fail
  and the gate records an error.
- Auto-discovers skills and MCP servers across Claude, Cursor, Windsurf, Gemini
  CLI and others; supports CI/CD and background (MDM) modes.
- Strengths: ASI04 (supply chain), ASI07 (MCP/inter-agent), credential handling.
- Free web alternative when you can't install the CLI: the Skill Inspector page.

## sentry/skill-scanner (community)
- Repo: https://github.com/getsentry/skills (skill on the agent-skills library)
- Install: `npx skills add https://github.com/getsentry/skills --skill skill-scanner`
- It is itself an **agent skill**, but it bundles a runnable static scanner at
  `skill-scanner/scripts/scan_skill.py`.
- Detected as: that bundled script under a known skills dir
  (`~/.agents/skills`, `~/.claude/skills`, or any `--skills-dir` you add), run
  with `uv run` if available, else `python`.
- Detects: prompt injection, malicious code (exfiltration, reverse shells,
  credential theft), excessive permissions, secret exposure, supply-chain /
  remote-instruction loading. Emits JSON with severity counts.
- Strengths: install-time orientation; good ASI01/ASI03/ASI04 overlap as a
  cross-check against the others.

## Adding another scanner

The registry lives in `scanner_definitions()` in `scripts/run_scanners.py`. A new
entry needs: an `id`/`name`/`url`, a detection probe (`shutil.which(...)` or a
bundled-script lookup), a command template, an install hint, and trust notes.
The normalizer already handles common JSON shapes and raw-text fallback, so most
tools need no parser changes. Keep the "detect, never auto-install" contract.
