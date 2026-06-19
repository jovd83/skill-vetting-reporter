# OWASP Agentic Skills Top 10 (AST01–AST10)

A working reading of the **OWASP Agentic Skills Top 10** — the OWASP project
written specifically for the security of *AI agent skills* (the SKILL.md /
manifest unit of agent behaviour), covering the OpenClaw (SKILL.md YAML),
Claude Code (skill.json), Cursor/Codex (manifest.json) and VS Code
(package.json) ecosystems. This file maps each AST item to *what it looks like
inside a skill*, *what the automated gate catches*, and *what a human reviewer
still has to decide*.

Use it two ways:
- As the grounding for the **§4 AST coverage map** in every vetting report.
- As a checklist when a finding is ambiguous and you need to reason about impact.

> Source: **OWASP Agentic Skills Top 10**, v1.0 (2026 edition) —
> https://owasp.org/www-project-agentic-skills-top-10/ . At time of writing this
> is an **active OWASP project proposal**, so IDs and wording may still change;
> always treat the published OWASP pages as authoritative over this summary. The
> project also ships an assessment checklist and a skill-scanner integration page.
> (The broader **OWASP Top 10 for Agentic Applications**, ASI01–ASI10, remains a
> useful companion for agentic *systems* — but AST is the skill-specific list.)

## Contents
- [How detection maps to the skill](#how-detection-maps-to-the-skill)
- [AST01 — Malicious Skills](#ast01--malicious-skills)
- [AST02 — Supply Chain Compromise](#ast02--supply-chain-compromise)
- [AST03 — Over-Privileged Skills](#ast03--over-privileged-skills)
- [AST04 — Insecure Metadata](#ast04--insecure-metadata)
- [AST05 — Unsafe Deserialization](#ast05--unsafe-deserialization)
- [AST06 — Weak Isolation](#ast06--weak-isolation)
- [AST07 — Update Drift](#ast07--update-drift)
- [AST08 — Poor Scanning](#ast08--poor-scanning)
- [AST09 — No Governance](#ast09--no-governance)
- [AST10 — Cross-Platform Reuse](#ast10--cross-platform-reuse)

## How detection maps to the skill

Three layers cover these risks, in order of confidence:

1. **External scanner gate** (`run_scanners.py`) — Cisco skill-scanner, NVIDIA
   SkillSpector, Snyk Agent Scan, sentry/skill-scanner. Signature + semantic +
   behavioural/dataflow analysis. Strongest coverage for AST01, AST02, AST05.
2. **Heuristic scanner** (`vet_skill.py`) — fast regex/structure pass that flags
   *candidate* patterns by category. Good at locating evidence; it does not
   judge intent.
3. **Human reviewer** — the only control that actually understands purpose and
   context. The process/governance items (AST08–AST10) lean almost entirely on
   this layer; the tools can point, but the reviewer decides.

No layer "passes" a skill. A clean scan means *no known pattern matched* — never
*safe*.

---

## AST01 — Malicious Skills

**In a skill:** the skill is deliberately hostile — a credential stealer,
reverse shell, backdoor, or social-engineering instructions embedded in SKILL.md
prose. Skills run with the host agent's full permissions, so a malicious one
reaches API keys, SSH/wallet files, browser data, and the shell. Snyk's
ToxicSkills research found malicious skills combine *both* a code layer (scripts,
subprocess) and a natural-language instruction layer.

**Gate / heuristic signal:** `Injection/override`, `Concealment`,
`Hidden content`, `Authority claim`, `Exfiltration channel`, `Credential access`,
`Runtime download+exec`. SkillSpector/Cisco semantic + behavioural analysis.

**Reviewer must judge:** Read the whole SKILL.md as untrusted input. Is there
hidden/injected instruction text, credential harvesting, or an exfiltration sink
that betrays intent a regex can't confirm?

## AST02 — Supply Chain Compromise

**In a skill:** a legitimate publisher's account is hijacked, or a skill is
modified after publication, injecting malicious behaviour without the user's
awareness; or it pulls unpinned dependencies / remote payloads that a poisoned
upstream can swap.

**Gate / heuristic signal:** `Dependency`, `External domains`, `Binary content`,
`Runtime download+exec`; SkillSpector "Supply Chain", Snyk auto-discovery.

**Reviewer must judge:** Is every dependency pinned to an immutable hash, named,
and from a verified source with provenance/transparency? Any binary blob or
runtime fetch should push toward Tier 3 or reject.

## AST03 — Over-Privileged Skills

**In a skill:** requests or uses more capability than its function needs —
read/write to identity files, unrestricted network, shell execution — beyond
what the stated purpose requires.

**Gate / heuristic signal:** `Permissions`, `Privilege`, `Credential access`,
`Dynamic execution`, `Network call`; SkillSpector "Tool Misuse" / least-privilege.

**Reviewer must judge:** Is every powerful action *necessary* for what the skill
claims to do? Excess capability is the vulnerability even if nothing malicious
fires today.

## AST04 — Insecure Metadata

**In a skill:** the description, author, version, or permission declarations make
false claims — enabling typosquatting and impersonation — or simply don't match
the actual behaviour.

**Gate / heuristic signal:** `Metadata` (missing/invalid frontmatter, control
chars), `Authority claim`; plus the manual description-vs-behaviour check.

**Reviewer must judge:** Do the frontmatter name/description/author/version match
reality, and is the author the genuine publisher? A description-vs-behaviour
mismatch is a reject on its own.

## AST05 — Unsafe Deserialization

**In a skill:** YAML/JSON config (or a `pickle`/`marshal` load) executes
arbitrary code through dangerous parser tags or unvalidated input during skill
loading.

**Gate / heuristic signal:** `Dynamic execution` (pickle/marshal/`yaml.load`),
`Obfuscation`; SkillSpector AST/taint analysis.

**Reviewer must judge:** Does the skill parse config in a way that can execute
code? Require safe parsers (`yaml.safe_load`), no `pickle`/`marshal` on untrusted
data, dangerous tags disabled, and schema validation.

## AST06 — Weak Isolation

**In a skill:** code runs in *host mode* with direct access to the user's file
system, network, and processes instead of a container/sandbox — and side files
the toolchain auto-runs (`*.test.ts`, `conftest.py`, git hooks, CI, `setup.py`)
get the same access.

**Gate / heuristic signal:** `Dynamic execution`, `Runtime download+exec`,
`Toolchain auto-execution`; Cisco behavioural dataflow.

**Reviewer must judge:** Does it need host-mode access, or could it run sandboxed?
Open every auto-executed side file — these are the most common place for a
smuggled payload.

## AST07 — Update Drift

**In a skill:** dependencies use version *ranges* instead of pinned hashes, so a
malicious update can silently replace trusted code after the skill was approved.

**Gate / heuristic signal:** `Dependency` (unpinned `pip`/`npm` installs).

**Reviewer must judge:** Are all (including nested) dependencies pinned to
immutable hashes, with no wildcard/range versioning? Re-vet and re-pin the exact
commit on every version change.

## AST08 — Poor Scanning

**In a skill:** the skill relies on the *consumer* using a weak, single,
pattern-matching scanner — and uses obfuscation, hidden/zero-width content, or
natural-language-only instructions that signature scanners miss.

**Gate / heuristic signal:** `Obfuscation`, `Concealment`, `Hidden content`
(anti-analysis content); plus how many scanners actually ran in §0.

**Reviewer must judge:** Could this skill evade pattern matching? Did the gate
(§0) run more than one scanner, and does it combine semantic + behavioural
analysis — not signatures alone?

## AST09 — No Governance

**In a skill / in the org:** there is no skill inventory, approval workflow,
audit logging, or agent-identity isolation — skills get installed ad hoc with no
record of who approved what version.

**Gate / heuristic signal:** mostly process, not content (`Metadata` is a weak
proxy: a skill that can't even declare author/version is a governance smell).

**Reviewer must judge:** Is this skill going through an approval gate, recorded in
an inventory with approver + exact version, with the signed-off report (§7–§8)
kept as the audit log and agent identity isolated?

## AST10 — Cross-Platform Reuse

**In a skill:** a malicious or over-privileged skill is ported across platforms
(e.g. ClawHub → skills.sh, or a manifest from another ecosystem) *without
re-validation*, so one platform's miss is amplified everywhere.

**Gate / heuristic signal:** not statically detectable from content alone — a
process/governance judgement.

**Reviewer must judge:** Is this skill reused from another platform/registry
without re-validation here? Re-validate and re-sign on every import; never inherit
another platform's approval; pin the exact reviewed commit per platform.
