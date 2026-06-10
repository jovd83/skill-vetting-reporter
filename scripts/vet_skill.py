#!/usr/bin/env python3
"""skill-vetting-reporter: static heuristic scanner for AgentSkill packages.

Generates a draft vetting report (markdown) to support human review.
Static analysis only - never executes anything from the package under review.

Usage:
    python vet_skill.py <skill_dir_or_file> [-o report.md]
"""
import argparse, base64, hashlib, json, os, re, sys
from datetime import date
from pathlib import Path

SEV_CRIT, SEV_WARN, SEV_INFO = "CRITICAL", "WARNING", "INFO"

TEXT_EXT = {".md", ".txt", ".py", ".js", ".ts", ".tsx", ".jsx", ".sh", ".bash",
            ".zsh", ".yml", ".yaml", ".json", ".toml", ".cfg", ".ini", ".rb",
            ".ps1", ".bat", ".cmd", ".mjs", ".cjs", ".html", ".css", ".xml", ""}
EXEC_EXT = {".py", ".js", ".ts", ".tsx", ".jsx", ".sh", ".bash", ".zsh",
            ".rb", ".ps1", ".bat", ".cmd", ".mjs", ".cjs"}
BIN_EXT = {".exe", ".dll", ".so", ".dylib", ".bin", ".wasm", ".pyc",
           ".zip", ".tar", ".gz", ".7z", ".rar", ".jar"}

# (regex, severity, category, explanation)
PATTERNS = [
    # --- credential / secret access
    (r"~?/\.ssh|id_rsa|id_ed25519|authorized_keys", SEV_CRIT, "Credential access", "References SSH key material"),
    (r"~?/\.aws|AWS_SECRET|AWS_ACCESS_KEY", SEV_CRIT, "Credential access", "References AWS credentials"),
    (r"\.npmrc|\.pypirc|\.netrc|\.git-credentials", SEV_CRIT, "Credential access", "References credential config files"),
    (r"keychain|secretservice|wincred|libsecret", SEV_WARN, "Credential access", "References OS credential stores"),
    (r"for\s+\w+\s*(,\s*\w+)?\s+in\s+os\.environ|Object\.(keys|entries)\(\s*process\.env\s*\)|printenv|env\s*\|\s*", SEV_CRIT, "Credential access", "Enumerates environment variables (harvesting pattern)"),
    (r"(api[_-]?key|token|secret|password)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]", SEV_CRIT, "Hardcoded secret", "Possible hardcoded credential"),
    # --- exfiltration / network
    (r"curl\s+[^\n|]*\|\s*(ba)?sh|wget\s+[^\n|]*\|\s*(ba)?sh", SEV_CRIT, "Runtime download+exec", "Downloads and executes code (curl|sh pattern)"),
    (r"(requests\.(post|put)|urllib\.request|fetch\(|axios\.(post|put)|XMLHttpRequest|websocket)", SEV_WARN, "Network call", "Outbound network call - verify destination & payload"),
    (r"curl\s|wget\s|Invoke-WebRequest", SEV_WARN, "Network call", "Shell-level network download"),
    (r"webhook|ngrok|requestbin|burpcollaborator|pipedream\.net", SEV_CRIT, "Exfiltration channel", "Known exfiltration/callback channel reference"),
    # --- obfuscation / dynamic exec
    (r"base64\.b64decode|atob\(|frombase64string", SEV_WARN, "Obfuscation", "Base64 decoding - inspect what is decoded"),
    (r"\beval\s*\(|\bexec\s*\(|new\s+Function\s*\(|child_process|subprocess\.(run|Popen|call)|os\.system|os\.popen", SEV_WARN, "Dynamic execution", "Executes commands or dynamic code - inspect inputs"),
    (r"[A-Za-z0-9+/]{120,}={0,2}", SEV_WARN, "Obfuscation", "Long base64-like blob"),
    (r"\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){7,}", SEV_WARN, "Obfuscation", "Hex-escaped payload"),
    # --- persistence / scope escape
    (r"~?/\.(bashrc|zshrc|profile|bash_profile)|/etc/profile", SEV_CRIT, "Persistence", "Writes/refers to shell startup files"),
    (r"crontab|systemd|launchctl|schtasks|Register-ScheduledTask", SEV_WARN, "Persistence", "Scheduled task / service installation"),
    (r"\.git/hooks|pre-commit\b.*install|husky", SEV_WARN, "Persistence", "Git hook installation - runs on developer actions"),
    (r"CLAUDE\.md|AGENTS?\.md|\.cursorrules|settings\.json.*(append|write)|memory\.(md|json)", SEV_WARN, "Agent-config tampering", "Touches agent config/memory files - behaviour may persist after removal"),
    (r"chmod\s+\+x|icacls|takeown", SEV_INFO, "Permissions", "Changes file permissions"),
    (r"sudo\s|runas\s|--privileged", SEV_WARN, "Privilege", "Requests elevated privileges"),
    # --- prompt-injection / concealment (instruction files)
    (r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions", SEV_CRIT, "Injection/override", "Classic instruction-override phrase"),
    (r"do\s*n[o']t\s+(tell|show|mention|inform|reveal)\s+(this\s+to\s+)?the\s+user|without\s+(telling|informing|notifying)\s+the\s+user|hide\s+this\s+from\s+the\s+user", SEV_CRIT, "Concealment", "Instructs the agent to hide behaviour from the user"),
    (r"you\s+(now\s+)?have\s+(full\s+)?permission|this\s+(action\s+)?is\s+pre-?approved|no\s+confirmation\s+(is\s+)?needed", SEV_WARN, "Authority claim", "Claims pre-authorization - governance bypass attempt"),
    (r"(always|silently)\s+(run|execute|send|upload|forward)", SEV_WARN, "Concealment", "Unconditional/silent action instruction"),
    (r"[\u200b\u200c\u200d\u2060\ufeff]", SEV_CRIT, "Hidden content", "Zero-width characters (possible hidden instructions)"),
    # --- dependency hygiene
    (r"pip\s+install\s+(?![^\n]*==)[a-zA-Z]", SEV_INFO, "Dependency", "Unpinned pip install"),
    (r"npm\s+install\s+(?![^\n]*@\d)[a-zA-Z]|npx\s+(?!skills\b)[a-zA-Z]", SEV_INFO, "Dependency", "Unpinned npm install / npx execution"),
]

# OWASP Top 10 for Agentic Applications (v1.0, 2025-12-09) mapped to the
# heuristic categories above. Each entry: (id, name, [categories that signal it],
# what a human still has to judge that static heuristics cannot). The report
# uses this to show, per OWASP risk, whether anything fired and where the
# reviewer's own judgement remains the real control.
OWASP_ASI = [
    ("ASI01", "Agent Goal Hijack",
     ["Injection/override", "Concealment", "Hidden content", "Authority claim"],
     "Read the full SKILL.md as data: do any instructions try to redirect the agent's goal, hide steps, or claim pre-authorization?"),
    ("ASI02", "Tool Misuse & Exploitation",
     ["Dynamic execution", "Permissions", "Privilege"],
     "Does the skill use granted tools/commands for anything beyond its stated purpose?"),
    ("ASI03", "Identity & Privilege Abuse",
     ["Credential access", "Hardcoded secret", "Privilege"],
     "Does it touch credentials, tokens, or elevation it has no business needing?"),
    ("ASI04", "Agentic Supply Chain",
     ["Dependency", "External domains", "Binary content", "Runtime download+exec"],
     "Are all dependencies/domains pinned, named, and trusted? Any unreviewable binary or remote payload?"),
    ("ASI05", "Unexpected Code Execution",
     ["Runtime download+exec", "Dynamic execution", "Obfuscation", "Toolchain auto-execution"],
     "Can natural-language or side files (tests/hooks/CI) reach an exec path you did not expect?"),
    ("ASI06", "Memory & Context Poisoning",
     ["Agent-config tampering", "Persistence"],
     "Does it write to agent memory/config that would outlive this skill and reshape future runs?"),
    ("ASI07", "Insecure Inter-Agent Communication",
     ["Network call", "Exfiltration channel"],
     "Where does outbound traffic go, and could another agent/tool be spoofed or fed poisoned messages?"),
    ("ASI08", "Cascading Failures",
     ["Authority claim", "Concealment"],
     "Could one bad output trigger unconditional/automated downstream actions with no checkpoint?"),
    ("ASI09", "Human-Agent Trust Exploitation",
     ["Concealment", "Authority claim"],
     "Does the description match actual behaviour, or does confident framing nudge a reviewer to wave it through?"),
    ("ASI10", "Rogue Agents",
     ["Concealment", "Persistence", "Exfiltration channel", "Agent-config tampering"],
     "Taken together, is there a coherent pattern of hidden, self-directed, or persistent behaviour?"),
]

URL_RE = re.compile(r"https?://([a-zA-Z0-9.-]+)")
ALLOWLIST_DOMAINS = {"github.com", "raw.githubusercontent.com", "agentskills.io",
                     "anthropic.com", "docs.claude.com", "platform.claude.com",
                     "skills.sh", "npmjs.com", "pypi.org", "owasp.org"}
TOOLCHAIN_FILES = [
    (re.compile(r".*\.(test|spec)\.(ts|tsx|js|jsx|mjs|cjs)$"), "JS test file - auto-executed by Jest/Vitest on `npm test` or IDE save"),
    (re.compile(r"(^|/)conftest\.py$|.*_test\.py$|(^|/)test_.*\.py$"), "Python test file - auto-collected by pytest"),
    (re.compile(r"(^|/)\.github/workflows/.*\.ya?ml$"), "CI workflow - executed by CI on push"),
    (re.compile(r"(^|/)(pre-commit|post-checkout|post-merge|pre-push)$"), "Git hook"),
    (re.compile(r"(^|/)(Makefile|justfile|Taskfile\.ya?ml)$"), "Task runner file - may be invoked implicitly"),
    (re.compile(r"(^|/)(setup\.py|postinstall.*|\.husky/.*)$"), "Install-time hook - runs on package install"),
]


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()[:16]


def is_hidden(rel: str) -> bool:
    return any(part.startswith(".") and part not in (".", "..") for part in Path(rel).parts)


def scan_text(rel: str, text: str, findings: list):
    lines = text.splitlines()
    for rx, sev, cat, why in PATTERNS:
        for m in re.finditer(rx, text, re.IGNORECASE):
            line_no = text[:m.start()].count("\n") + 1
            snippet = lines[line_no - 1].strip()[:160] if line_no <= len(lines) else ""
            findings.append({"sev": sev, "cat": cat, "why": why,
                             "loc": f"{rel}:{line_no}", "evidence": snippet})
    # HTML comments in markdown (hidden-from-render instructions)
    if rel.endswith(".md"):
        for m in re.finditer(r"<!--(.*?)-->", text, re.DOTALL):
            content = m.group(1).strip()
            if len(content) > 40:
                line_no = text[:m.start()].count("\n") + 1
                findings.append({"sev": SEV_WARN, "cat": "Hidden content",
                                 "why": "Long HTML comment in markdown (invisible when rendered)",
                                 "loc": f"{rel}:{line_no}", "evidence": content[:160]})
    # very long lines (minified/obfuscated)
    for i, ln in enumerate(lines, 1):
        if len(ln) > 1500:
            findings.append({"sev": SEV_WARN, "cat": "Obfuscation",
                             "why": f"Very long line ({len(ln)} chars) - possible minified/encoded payload",
                             "loc": f"{rel}:{i}", "evidence": ln[:120] + "..."})


def parse_frontmatter(text: str):
    m = re.match(r"^---\s*\n(.*?)\n---", text, re.DOTALL)
    if not m:
        return None
    fm = {}
    lines = m.group(1).splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        # only treat unindented, non-list lines as keys (skips nested mappings
        # like `metadata:`'s children and `- list` items)
        if ":" in line and not line[:1].isspace() and not line.lstrip().startswith("-"):
            k, _, v = line.partition(":")
            key, val = k.strip(), v.strip()
            # YAML block scalars (`>` folded, `|` literal, with optional chomping):
            # gather the following indented/blank lines as the value so a
            # `description: >` shows its real text instead of just ">".
            if val and val[0] in "|>" and val.strip("|>+-0123456789") == "":
                block, i = [], i + 1
                while i < len(lines) and (not lines[i].strip() or lines[i][:1].isspace()):
                    block.append(lines[i].strip())
                    i += 1
                fm[key] = " ".join(b for b in block if b).strip()
                continue
            fm[key] = val.strip("\"'")
        i += 1
    return fm


def load_scanner_gate(path):
    """Load the JSON produced by run_scanners.py. Returns None if absent/unreadable
    so the report can fall back to 'gate not run'."""
    if not path:
        return None
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if data.get("schema", "").startswith("skill-vetting-reporter/scanner-gate"):
            return data
    except Exception:
        return None
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("-o", "--output", default="vetting_report.md")
    ap.add_argument("--scanners", default=None,
                    help="path to scanner_results.json from run_scanners.py (the external scanner gate)")
    args = ap.parse_args()
    gate = load_scanner_gate(args.scanners)

    root = Path(args.target).resolve()
    if not root.exists():
        sys.exit(f"Not found: {root}")
    files = [root] if root.is_file() else sorted(
        p for p in root.rglob("*") if p.is_file() and "node_modules" not in p.parts)
    base = root.parent if root.is_file() else root

    inventory, findings, domains, toolchain_hits = [], [], {}, []
    skill_md_text, fm = None, None

    for p in files:
        rel = str(p.relative_to(base))
        ext = p.suffix.lower()
        size = p.stat().st_size
        kind = "binary/archive" if ext in BIN_EXT else ("executable" if ext in EXEC_EXT else "text")
        inventory.append({"rel": rel, "size": size, "kind": kind,
                          "hash": sha256(p), "hidden": is_hidden(rel)})
        if ext in BIN_EXT:
            findings.append({"sev": SEV_CRIT, "cat": "Binary content",
                             "why": "Binary/archive cannot be reviewed as text - Tier 3 or reject",
                             "loc": rel, "evidence": f"{size} bytes"})
            continue
        for rx, why in TOOLCHAIN_FILES:
            if rx.search(rel):
                toolchain_hits.append((rel, why))
                findings.append({"sev": SEV_CRIT, "cat": "Toolchain auto-execution",
                                 "why": why, "loc": rel, "evidence": "file present"})
        if is_hidden(rel):
            findings.append({"sev": SEV_INFO, "cat": "Hidden file",
                             "why": "Dotfile/dot-directory - easy to overlook in review",
                             "loc": rel, "evidence": ""})
        if ext in TEXT_EXT or size < 512_000:
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            scan_text(rel, text, findings)
            for m in URL_RE.finditer(text):
                d = m.group(1).lower()
                domains.setdefault(d, 0)
                domains[d] += 1
            if p.name == "SKILL.md":
                skill_md_text = text
                fm = parse_frontmatter(text)

    # frontmatter checks
    if skill_md_text is not None:
        if not fm:
            findings.append({"sev": SEV_WARN, "cat": "Metadata",
                             "why": "SKILL.md has no YAML frontmatter", "loc": "SKILL.md:1", "evidence": ""})
        else:
            for key in ("name", "description"):
                if key not in fm:
                    findings.append({"sev": SEV_WARN, "cat": "Metadata",
                                     "why": f"Frontmatter missing '{key}'", "loc": "SKILL.md:1", "evidence": ""})
        # A control character in the YAML frontmatter (a stray TAB, or a C1
        # control such as U+009D from a mangled em-dash) is invalid YAML: it
        # breaks strict parsers (e.g. Cisco skill-scanner) while lenient ones load
        # fine. Worth flagging as a quality issue AND a mild anti-analysis signal
        # (content that defeats one scanner but not another). run_scanners.py
        # works around it with a normalized-copy retry; we still record it here.
        m_fm = re.match(r"^---\s*\n(.*?)\n---", skill_md_text, re.DOTALL)
        if m_fm:
            bad = re.search(r"[\x00-\x08\x09\x0b\x0c\x0e-\x1f\x7f-\x9f]", m_fm.group(1))
            if bad:
                cp = ord(bad.group())
                line = skill_md_text[:m_fm.start(1) + bad.start()].count("\n") + 1
                findings.append({"sev": SEV_WARN, "cat": "Metadata",
                                 "why": f"Control character U+{cp:04X} in YAML frontmatter - invalid YAML; "
                                        "breaks strict parsers (scanner coverage gap) and is a mild "
                                        "anti-analysis signal",
                                 "loc": f"SKILL.md:{line}", "evidence": f"U+{cp:04X} at frontmatter offset {bad.start()}"})
    elif root.is_dir():
        findings.append({"sev": SEV_WARN, "cat": "Metadata",
                         "why": "No SKILL.md found in package", "loc": str(root), "evidence": ""})

    unknown_domains = {d: c for d, c in domains.items()
                       if not any(d == a or d.endswith("." + a) for a in ALLOWLIST_DOMAINS)}
    if unknown_domains:
        findings.append({"sev": SEV_WARN, "cat": "External domains",
                         "why": "Non-allowlisted domains referenced - verify each",
                         "loc": "-", "evidence": ", ".join(sorted(unknown_domains))[:300]})

    crit = [f for f in findings if f["sev"] == SEV_CRIT]
    warn = [f for f in findings if f["sev"] == SEV_WARN]
    info = [f for f in findings if f["sev"] == SEV_INFO]
    has_exec = any(i["kind"] == "executable" for i in inventory)
    has_bin = any(i["kind"] == "binary/archive" for i in inventory)

    if has_bin or len(crit) >= 2:
        tier, tier_why = "REJECT / Tier 3", "binaries present or 2+ critical findings"
    elif crit:
        tier, tier_why = "Tier 3 (deep review)", "at least one critical finding to confirm or dismiss"
    elif has_exec and warn:
        tier, tier_why = "Tier 2 (standard review)", "executable content with warnings"
    elif has_exec or warn:
        tier, tier_why = "Tier 1-2 (depends on source & blast radius)", "executable content or warnings present"
    else:
        tier, tier_why = "Tier 0-1 (depends on source & blast radius)", "instructions-only, no known patterns detected"

    # --- external scanner gate (run_scanners.py) folds into tier + report ----
    gate_verdict = gate["gate"] if gate else "NOT RUN"
    if gate and gate["gate"] == "BLOCK":
        tier = "REJECT / Tier 3"
        tier_why = "external scanner gate returned a blocking result (" + ", ".join(gate["blocking"]) + ")"

    def build_gate_section():
        if not gate:
            return ("> **Gate not run.** This is the mandatory automated pre-screen for any skill at "
                    "Tier 1 or above. Run `python scripts/run_scanners.py <target> -o scanner_results.json` "
                    "and re-run this report with `--scanners scanner_results.json`. A reviewer may only "
                    "proceed without it by recording an explicit exception below.\n")
        head = {"PASS": "at least one scanner ran and none returned a blocking result",
                "BLOCK": "a scanner flagged a high/critical risk; do not approve",
                "INCOMPLETE": "no scanner ran; Tier 1+ approval is not allowed until one does"}
        errored = sum(1 for r in gate["results"] if r["status"] == "error")
        out = [f"**Gate verdict: {gate['gate']}** — {head.get(gate['gate'], '')}",
               f"_Ran {gate['scanners_ran']} of {gate['scanners_total']} known scanners "
               f"at {gate['generated_utc']}._\n"]
        if errored:
            out.append(f"> ⚠ Partial coverage: {errored} scanner(s) errored (see table). "
                       f"A PASS here only reflects the scanners that completed.\n")
        out += ["| Scanner | Status | Findings / score | Block? |",
                "|---|---|---|---|"]
        retry_notes = []
        for r in gate["results"]:
            if r["status"] == "ran":
                sc = r.get("severity_counts", {})
                sev = ", ".join(f"{k}:{v}" for k, v in sc.items() if v) or "none"
                score = f" · score {r['risk_score']}" if r.get("risk_score") is not None else ""
                status_cell = "ran (retried)" if r.get("retry") else "ran"
                out.append(f"| {r['name']} | {status_cell} | {sev}{score} | {'**YES**' if r.get('block') else 'no'} |")
            elif r["status"] == "missing":
                out.append(f"| {r['name']} | _missing_ | install: `{r['install_hint']}` | — |")
            elif r["status"] == "skipped":
                out.append(f"| {r['name']} | _skipped_ | {r.get('skip_reason', '')} | — |")
            else:
                out.append(f"| {r['name']} | _error_ | `{str(r.get('error',''))[:80]}` | — |")
            if r.get("retry_note"):
                retry_notes.append(f"- _{r['name']}_ — {r['retry_note']}")
        if retry_notes:
            out.append("\n**Retries:**\n" + "\n".join(retry_notes))
        return "\n".join(out) + "\n"

    def build_owasp_section():
        cats_fired = {f["cat"] for f in findings}
        rows = ["| OWASP | Risk | Static signal | Reviewer must still judge |",
                "|---|---|---|---|"]
        for asi_id, asi_name, cats, manual in OWASP_ASI:
            hit = [c for c in cats if c in cats_fired]
            signal = ("⚠ " + ", ".join(sorted(set(hit)))) if hit else "clear"
            rows.append(f"| **{asi_id}** | {asi_name} | {signal} | {manual} |")
        legend = ("\n_⚠ = a heuristic in this category fired (see §3); 'clear' = no pattern matched, "
                  "which is **not** proof of safety. The external scanner gate (§0) adds semantic & "
                  "behavioural coverage. Full taxonomy: OWASP Top 10 for Agentic Applications v1.0 "
                  "(2025-12-09) — see references/owasp-top10-agent-skills.md._\n")
        return "\n".join(rows) + legend

    def fmt(fl):
        if not fl:
            return "_None detected._\n"
        out = ""
        for f in fl:
            out += f"- **[{f['cat']}]** {f['why']}\n  - `{f['loc']}`"
            if f["evidence"]:
                out += f" — `{f['evidence']}`"
            out += "\n  - Reviewer judgement: ☐ confirmed ☐ false positive ☐ documented-not-performed — notes: ____\n"
        return out

    name = (fm or {}).get("name", root.name)
    rf = lambda cond: "⚠ check findings" if cond else "☐"
    report = f"""# Skill Vetting Report — `{name}`

> Draft generated by skill-vetting-reporter on {date.today().isoformat()}. Static heuristics + external scanner gate.
> **"No findings" means no known patterns matched — it does NOT mean the skill is safe.**
> A human reviewer must complete every judgement section before any approval.

## 0. External scanner gate (mandatory for Tier 1+)
{build_gate_section()}
## 1. Identity
| Field | Value |
|---|---|
| Skill name | {name} |
| Path scanned | `{root}` |
| Files | {len(inventory)} ({sum(1 for i in inventory if i['kind']=='executable')} executable, {sum(1 for i in inventory if i['kind']=='binary/archive')} binary/archive) |
| Frontmatter description | {(fm or {}).get('description', '_(none)_')[:300]} |
| Version / commit pinned | _(reviewer: fill in exact hash)_ |
| Source classification | ☐ Internal ☐ Verified vendor ☐ Known community ☐ Unknown |

## 2. File inventory
| File | Kind | Size | SHA-256 (16) | Hidden |
|---|---|---|---|---|
""" + "".join(f"| `{i['rel']}` | {i['kind']} | {i['size']} | `{i['hash']}` | {'yes' if i['hidden'] else ''} |\n" for i in inventory) + f"""
## 3. Findings

### Critical ({len(crit)})
{fmt(crit)}
### Warnings ({len(warn)})
{fmt(warn)}
### Info ({len(info)})
{fmt(info)}
### External domains referenced
{chr(10).join(f"- `{d}` ({c}x){' — NOT on allowlist' if d in unknown_domains else ''}" for d, c in sorted(domains.items())) if domains else "_None._"}

## 4. OWASP Top 10 for Agentic Applications — coverage map
{build_owasp_section()}
## 5. Red-flag checklist (auto-prefilled where detectable)
- {rf(any(f['cat']=='Obfuscation' for f in findings))} Obfuscated/encoded payloads
- {rf(any(f['cat']=='Runtime download+exec' for f in findings))} Runtime download & execute
- {rf(any(f['cat'] in ('Credential access','Hardcoded secret') for f in findings))} Credential/secret access
- {rf(any(f['cat'] in ('Concealment','Injection/override','Hidden content') for f in findings))} Concealment / instruction override / hidden content
- {rf(any(f['cat'] in ('Persistence','Agent-config tampering') for f in findings))} Persistence outside skill directory
- ☐ Description vs. actual behaviour mismatch _(manual check — read full SKILL.md)_
- {rf(bool(toolchain_hits))} Toolchain auto-executed side files
- {rf(bool(unknown_domains))} Unexplained hardcoded URLs/domains
- ☐ Publisher impersonation _(manual check — verify exact account name)_
- {rf(any(f['cat']=='Authority claim' for f in findings))} Pressure/authority framing
- {('⚠ BLOCK' if gate_verdict=='BLOCK' else ('⚠ INCOMPLETE' if gate_verdict=='INCOMPLETE' else ('☐' if gate_verdict=='NOT RUN' else '✓ passed')))} External scanner gate (§0) clean

## 6. Suggested review tier
**{tier}** — {tier_why}.
Adjust for source (verified vendor may lower by one tier) and blast radius
(credentials / sensitive data / org-wide rollout forces Tier 3).
Gate state: **{gate_verdict}** — a BLOCK forces reject/escalate; INCOMPLETE blocks Tier 1+ approval until a scanner runs.

## 7. Reviewer judgement (mandatory)
- External scanner gate reviewed (§0): ☐ yes — verdict: {gate_verdict}
- Description alignment verified: ☐ yes ☐ no — notes: ____
- All flagged locations read in full: ☐ yes
- OWASP coverage map (§4) walked, each ⚠ resolved: ☐ yes
- Sandbox behavioural test performed (Tier 2+): ☐ yes ☐ n/a — observations: ____
- Additional scanner run manually (name + version + result): ____
- Final tier: ____  Final verdict: ☐ Approve ☐ Approve with conditions ☐ Escalate ☐ Reject

## 8. Sign-off
| Role | Name | Date |
|---|---|---|
| Reviewer | | |
| Second reviewer (Tier 2+) | | |
| Security team (Tier 3) | | |

Re-review due: ____ (or on any version change)
"""
    Path(args.output).write_text(report, encoding="utf-8")
    print(json.dumps({"files": len(inventory), "critical": len(crit), "warnings": len(warn),
                      "info": len(info), "suggested_tier": tier, "scanner_gate": gate_verdict,
                      "report": args.output}))


if __name__ == "__main__":
    main()
