# OWASP Top 10 for Agent Skills

A skill-focused reading of the **OWASP Top 10 for Agentic Applications, v1.0**
(OWASP GenAI Security Project, published 2025-12-09), the benchmark taxonomy for
autonomous-AI risk. An AgentSkill is a small, distributable unit of agent
behaviour — instructions plus optional scripts and assets — so it is exactly the
kind of "runtime component" that several of these risks warn about. This file
maps each ASI item to *what it looks like inside a skill*, *what the automated
gate catches*, and *what a human reviewer still has to decide*.

Use it two ways:
- As the grounding for the **§4 OWASP coverage map** in every vetting report.
- As a checklist when a finding is ambiguous and you need to reason about impact.

> Source: OWASP Top 10 for Agentic Applications v1.0 (ASI01–ASI10) and the
> companion *Agentic AI – Threats and Mitigations v1.1*. It builds on the
> OWASP Top 10 for LLM Applications 2025 (LLM01–LLM10); the mapping to those IDs
> is noted per item. Always treat the published OWASP documents as authoritative
> over this summary.

## Contents
- [How detection maps to the skill](#how-detection-maps-to-the-skill)
- [ASI01 — Agent Goal Hijack](#asi01--agent-goal-hijack)
- [ASI02 — Tool Misuse & Exploitation](#asi02--tool-misuse--exploitation)
- [ASI03 — Identity & Privilege Abuse](#asi03--identity--privilege-abuse)
- [ASI04 — Agentic Supply Chain Vulnerabilities](#asi04--agentic-supply-chain-vulnerabilities)
- [ASI05 — Unexpected Code Execution](#asi05--unexpected-code-execution)
- [ASI06 — Memory & Context Poisoning](#asi06--memory--context-poisoning)
- [ASI07 — Insecure Inter-Agent Communication](#asi07--insecure-inter-agent-communication)
- [ASI08 — Cascading Failures](#asi08--cascading-failures)
- [ASI09 — Human-Agent Trust Exploitation](#asi09--human-agent-trust-exploitation)
- [ASI10 — Rogue Agents](#asi10--rogue-agents)

## How detection maps to the skill

Three layers cover these risks, in order of confidence:

1. **External scanner gate** (`run_scanners.py`) — Cisco skill-scanner, NVIDIA
   SkillSpector, Snyk Agent Scan, sentry/skill-scanner. Signature + semantic +
   behavioural/dataflow analysis. Strongest coverage for ASI01, ASI04, ASI05.
2. **Heuristic scanner** (`vet_skill.py`) — fast regex/structure pass that flags
   *candidate* patterns by category. Good at locating evidence; it does not
   judge intent.
3. **Human reviewer** — the only control that actually understands purpose and
   context. ASI06–ASI10 lean heavily on this layer; the tools can point, but the
   reviewer decides.

No layer "passes" a skill. A clean scan means *no known pattern matched* — never
*safe*.

---

## ASI01 — Agent Goal Hijack
*(maps to LLM01 Prompt Injection)*

**In a skill:** the SKILL.md body, a referenced doc, or a comment contains text
that redirects the agent away from the task the user asked for — "ignore previous
instructions", hidden HTML comments, zero-width characters, or framing that
quietly substitutes a different objective (the EchoLeak class of attack). The
skill's instructions are *data*, but a careless agent will treat them as
commands.

**Gate / heuristic signal:** `Injection/override`, `Concealment`,
`Hidden content`, `Authority claim`. SkillSpector "Prompt Injection" (5 patterns)
and Cisco LLM semantic analysis target this directly.

**Reviewer must judge:** Read the whole SKILL.md as untrusted input. Does any
instruction try to change the goal, suppress a step, or speak to the agent rather
than describe a task? Subtle reframing will not trip a regex.

## ASI02 — Tool Misuse & Exploitation
*(maps to LLM06 Excessive Agency)*

**In a skill:** legitimate tools are used in unsafe ways — shelling out,
spawning subprocesses, broad file globbing, or invoking a granted capability for
something outside the stated purpose (the Amazon Q class).

**Gate / heuristic signal:** `Dynamic execution`, `Permissions`, `Privilege`;
SkillSpector "Tool Misuse" and "MCP Tool Poisoning".

**Reviewer must judge:** Is every powerful action *necessary* for what the skill
claims to do? Excess capability is the vulnerability even if nothing malicious
fires today.

## ASI03 — Identity & Privilege Abuse
*(maps to LLM06 Excessive Agency / LLM02 Sensitive Information Disclosure)*

**In a skill:** reads SSH/AWS/npm credentials, enumerates environment variables,
embeds a token, or requests elevation (`sudo`, `runas`, `--privileged`) it has no
reason to need. Leaked credentials let the agent operate far beyond its scope.

**Gate / heuristic signal:** `Credential access`, `Hardcoded secret`,
`Privilege`; SkillSpector "Privilege Escalation", Snyk credential-handling checks.

**Reviewer must judge:** Does the skill touch identity or secrets at all? If so,
is there a stated, legitimate reason, and is the scope minimal?

## ASI04 — Agentic Supply Chain Vulnerabilities
*(maps to LLM03 Supply Chain)*

**In a skill:** unpinned `pip`/`npm` installs, dependencies pulled from
non-allowlisted domains, an unreviewable binary or archive, or instructions that
load remote content at runtime (the GitHub-MCP exploit class). Each is an entry
point for a poisoned component.

**Gate / heuristic signal:** `Dependency`, `External domains`, `Binary content`,
`Runtime download+exec`; SkillSpector "Supply Chain" (6 patterns) and YARA
signatures, Snyk auto-discovery across agents.

**Reviewer must judge:** Is every dependency pinned, named, and from a trusted
source? Any binary blob or remote fetch should push toward Tier 3 or reject.

## ASI05 — Unexpected Code Execution
*(maps to LLM05 Improper Output Handling)*

**In a skill:** a natural-language path reaches an exec sink — `eval`/`exec`,
`curl | sh`, obfuscated/base64 payloads, or **side files the toolchain runs
automatically** (`*.test.ts`, `conftest.py`, git hooks, CI workflows,
`setup.py`). The skill body can look harmless while a test file does the work
(the AutoGPT RCE class).

**Gate / heuristic signal:** `Runtime download+exec`, `Dynamic execution`,
`Obfuscation`, `Toolchain auto-execution`; SkillSpector "Behavioral AST" (8) and
"Taint Tracking" (5), Cisco behavioural dataflow.

**Reviewer must judge:** Trace where untrusted input can flow. Open every
auto-executed side file — these are the most common place for a smuggled payload.

## ASI06 — Memory & Context Poisoning
*(maps to LLM04 Data and Model Poisoning)*

**In a skill:** writes to agent memory or config that outlives the skill —
`CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `settings.json`, `memory.json` — so
behaviour persists (and may stay malicious) even after the skill is removed (the
Gemini memory-attack class).

**Gate / heuristic signal:** `Agent-config tampering`, `Persistence`;
SkillSpector "Memory Poisoning".

**Reviewer must judge:** Should this skill write outside its own directory at
all? Persistent config edits are rarely justified and are hard to undo.

## ASI07 — Insecure Inter-Agent Communication
*(maps to LLM05 / agentic A2A threats)*

**In a skill:** opens outbound channels (webhooks, sockets, posts) to other
agents or services without verifying the peer, enabling spoofed or poisoned
messages to misdirect a cluster.

**Gate / heuristic signal:** `Network call`, `Exfiltration channel`; Snyk MCP
discovery, SkillSpector "MCP Least Privilege".

**Reviewer must judge:** Where does outbound traffic go, what does it carry, and
could the destination be spoofed or the payload be exfiltration disguised as
coordination?

## ASI08 — Cascading Failures
*(maps to LLM06 Excessive Agency / LLM09 Misinformation)*

**In a skill:** unconditional or "silent" actions, or framing that encourages the
agent to chain steps automatically, so one bad output amplifies through a
pipeline with no checkpoint.

**Gate / heuristic signal:** `Authority claim`, `Concealment` ("always/silently
run …"). Mostly a design judgement, not a pattern.

**Reviewer must judge:** Does the skill insert a human checkpoint before
high-impact or irreversible actions, or does it push for unattended automation?

## ASI09 — Human-Agent Trust Exploitation
*(maps to LLM09 Misinformation / social engineering)*

**In a skill:** the description and the behaviour diverge, or confident,
authoritative language nudges a reviewer/operator into approving something they
would otherwise question. **Description-vs-behaviour mismatch is a top red flag
even when no code pattern fires.**

**Gate / heuristic signal:** `Concealment`, `Authority claim`; otherwise manual.

**Reviewer must judge:** Do the frontmatter description and the full instructions
describe the *same* task? Is any "pre-approved / no confirmation needed" framing
trying to bypass governance?

## ASI10 — Rogue Agents
*(composite: LLM06 + LLM04 + behavioural)*

**In a skill:** the *combination* of hidden instructions, persistence, and an
exfiltration channel adds up to self-directed, concealed behaviour — even if each
piece alone looks minor (the Replit-meltdown class).

**Gate / heuristic signal:** co-occurrence of `Concealment`, `Persistence`,
`Exfiltration channel`, `Agent-config tampering`; SkillSpector "Rogue Agent".

**Reviewer must judge:** Step back from individual findings. Is there a coherent
story of hidden, persistent, self-directed action? If yes — reject and
quarantine, do not "approve with conditions".
