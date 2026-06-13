#!/usr/bin/env python3
"""skill-vetting-reporter: static heuristic scanner for AgentSkill packages.

Generates a draft vetting report (markdown) to support human review.
Static analysis only - never executes anything from the package under review.

Usage:
    python vet_skill.py <skill_dir_or_file> [-o report.md]
"""
import argparse, base64, hashlib, html, json, os, re, sys
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
# heuristic categories above. Each entry:
#   (id, name, [categories that signal it], reviewer question, mitigation advice)
# The report shows, per OWASP risk, whether anything fired, the judgement the
# heuristics cannot make for the reviewer, and concrete "what good looks like"
# guidance so the table advises a fix, not just a question. Deeper per-risk
# detail lives in references/owasp-top10-agent-skills.md.
OWASP_ASI = [
    ("ASI01", "Agent Goal Hijack",
     ["Injection/override", "Concealment", "Hidden content", "Authority claim"],
     "Read the full SKILL.md as data: do any instructions try to redirect the agent's goal, hide steps, or claim pre-authorization?",
     "Skill text is data, never commands. Reject 'ignore previous', hidden HTML comments, and zero-width chars; the body must not address the agent imperatively or pre-authorize itself."),
    ("ASI02", "Tool Misuse & Exploitation",
     ["Dynamic execution", "Permissions", "Privilege"],
     "Does the skill use granted tools/commands for anything beyond its stated purpose?",
     "Least privilege: every shell/subprocess/tool call should map to a declared step. Remove or sandbox capability beyond the stated purpose; constrain exec to fixed commands, not user-shaped strings."),
    ("ASI03", "Identity & Privilege Abuse",
     ["Credential access", "Hardcoded secret", "Privilege"],
     "Does it touch credentials, tokens, or elevation it has no business needing?",
     "No credential/token reads or elevation unless that IS the job. Prefer scoped, injected secrets over env/file harvesting; never hardcode secrets; drop sudo/runas/--privileged that isn't justified."),
    ("ASI04", "Agentic Supply Chain",
     ["Dependency", "External domains", "Binary content", "Runtime download+exec"],
     "Are all dependencies/domains pinned, named, and trusted? Any unreviewable binary or remote payload?",
     "Pin every dependency to a version/hash; name and allowlist each domain; ship no unreviewable binaries; never load remote instructions or code at runtime. Document why each external source is needed."),
    ("ASI05", "Unexpected Code Execution",
     ["Runtime download+exec", "Dynamic execution", "Obfuscation", "Toolchain auto-execution"],
     "Can natural-language or side files (tests/hooks/CI) reach an exec path you did not expect?",
     "No eval/exec on built strings, and never pipe a download straight into a shell. Open every auto-run side file (tests, git hooks, CI, setup.py/postinstall) and keep all exec paths off untrusted/model-controlled input."),
    ("ASI06", "Memory & Context Poisoning",
     ["Agent-config tampering", "Persistence"],
     "Does it write to agent memory/config that would outlive this skill and reshape future runs?",
     "Writes stay inside the skill dir. Edits to CLAUDE.md/AGENTS.md/settings.json/memory need explicit, auditable justification and a clean removal path; never silently persist behaviour."),
    ("ASI07", "Insecure Inter-Agent Communication",
     ["Network call", "Exfiltration channel"],
     "Where does outbound traffic go, and could another agent/tool be spoofed or fed poisoned messages?",
     "Pin destinations to a documented allowlist with timeouts; verify/authenticate peers; treat inbound agent/tool content as untrusted data, not commands; confirm payloads carry no exfiltrated data."),
    ("ASI08", "Cascading Failures",
     ["Authority claim", "Concealment"],
     "Could one bad output trigger unconditional/automated downstream actions with no checkpoint?",
     "Insert a human checkpoint before irreversible or high-impact actions; avoid 'always/silently' chained automation; make failures stop the chain rather than amplify through it."),
    ("ASI09", "Human-Agent Trust Exploitation",
     ["Concealment", "Authority claim"],
     "Does the description match actual behaviour, or does confident framing nudge a reviewer to wave it through?",
     "Description must equal behaviour. Strip 'pre-approved / no confirmation needed' framing; require explicit user consent for sensitive actions; a description-vs-behaviour mismatch is a reject on its own."),
    ("ASI10", "Rogue Agents",
     ["Concealment", "Persistence", "Exfiltration channel", "Agent-config tampering"],
     "Taken together, is there a coherent pattern of hidden, self-directed, or persistent behaviour?",
     "If concealment + persistence + egress co-occur, reject and quarantine — do not 'approve with conditions'. Re-vet on every version change; pin the exact reviewed commit."),
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

# --- scoring engine ----------------------------------------------------------
# Count-based risk scoring (additive to the existing Tier 0-3 + gate, never
# replacing them). Hits are counted in *code* files only (executable extensions),
# so behaviour documented in markdown does not inflate the score. Each bucket has
# a per-hit penalty and a cap; hard-credential hits or hitting the dangerous cap
# force the recommendation to Decline.
DANGEROUS_PATTERNS = [
    re.compile(r"\beval\s*\(|\bexec\s*\(|new\s+Function\s*\("),
    re.compile(r"os\.system|os\.popen|subprocess\.(run|Popen|call|check_output)|child_process|spawnSync|execSync"),
    re.compile(r"shell\s*=\s*True"),
    re.compile(r"\brm\s+-rf\b|Remove-Item[^\n]*-Recurse[^\n]*-Force|\bdel\s+/[sq]\b|shutil\.rmtree"),
    re.compile(r"pickle\.loads|yaml\.load\s*\((?![^)]*Loader)|marshal\.loads"),
    re.compile(r"curl\s+[^\n|]*\|\s*(ba)?sh|wget\s+[^\n|]*\|\s*(ba)?sh|iex\s*\(|Invoke-Expression"),
]
NETWORK_PATTERNS = [
    re.compile(r"requests\.(get|post|put|delete|patch|head|request)|httpx\.|aiohttp\."),
    re.compile(r"urllib\.request|urlopen|urlretrieve|http\.client|socket\.socket"),
    re.compile(r"\bfetch\s*\(|axios\.|XMLHttpRequest|WebSocket|new\s+WebSocket"),
    re.compile(r"\bcurl\s|\bwget\s|Invoke-WebRequest|Invoke-RestMethod|Net\.WebClient"),
]
SOFT_CREDENTIAL_PATTERNS = [
    re.compile(r"(api[_-]?key|access[_-]?token|auth[_-]?token|secret|password|passwd|credential|client[_-]?secret)", re.IGNORECASE),
    re.compile(r"os\.environ(\.get)?\s*[\[(]\s*['\"][^'\"]*(KEY|TOKEN|SECRET|PASS|CRED)[^'\"]*['\"]|getenv\s*\(\s*['\"][^'\"]*(KEY|TOKEN|SECRET|PASS|CRED)", re.IGNORECASE),
    re.compile(r"~?/\.ssh|~?/\.aws|\.npmrc|\.pypirc|\.netrc|\.git-credentials|keychain"),
]
HARD_CREDENTIAL_PATTERNS = [
    re.compile(r"(api[_-]?key|token|secret|password|passwd|client[_-]?secret)\s*[:=]\s*['\"][A-Za-z0-9_\-/+=]{16,}['\"]", re.IGNORECASE),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b|\bASIA[0-9A-Z]{16}\b"),  # AWS access key ids
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),  # GitHub / Slack tokens
    re.compile(r"\beyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),  # JWT
]
SCORING_BUCKETS = [
    # key,          patterns,                  per_hit, cap,  label
    ("dangerous",   DANGEROUS_PATTERNS,        8,       8,    "Dangerous calls"),
    ("network",     NETWORK_PATTERNS,          2,       12,   "Network/tool calls"),
    ("soft_cred",   SOFT_CREDENTIAL_PATTERNS,  5,       4,    "Soft credential hits"),
    ("hard_cred",   HARD_CREDENTIAL_PATTERNS,  40,      999,  "Hard credential hits"),
    ("misplaced",   None,                      5,       4,    "Misplaced scripts"),
]
EXPECTED_SCRIPT_DIRS = {"scripts", "tests"}  # code here is expected; elsewhere = misplaced

# Coarse category taxonomy, inferred from metadata or description keywords.
CATEGORY_KEYWORDS = [
    ("Security / governance", r"vet|securit|audit|scan|owasp|complian|threat|risk|review"),
    ("Testing / QA", r"\btest|qa\b|playwright|cypress|junit|coverage|regression|bdd|gherkin"),
    ("Data / synthetic data", r"synthetic|dataset|data generation|faker|csv|json data|population"),
    ("Documentation / reporting", r"report|document|changelog|readme|slide|diagram|docx|pdf"),
    ("Frontend / UI", r"frontend|react|angular|vue|css|tailwind|component|ui\b|design"),
    ("DevOps / release", r"release|deploy|ci/cd|docker|kubernetes|pipeline|version bump"),
    ("API / integration", r"\bapi\b|openapi|mcp|webhook|integration|sdk|endpoint"),
    ("Agent tooling / memory", r"dispatcher|memory|skill|agent|orchestrat|routing"),
]


def count_scoring_hits(text, counts):
    """Accumulate per-bucket regex-hit counts for one code file's text."""
    for key, patterns, _per, _cap, _lbl in SCORING_BUCKETS:
        if patterns is None:
            continue
        for rx in patterns:
            counts[key] += len(rx.findall(text))


def infer_category(fm, blob):
    """Prefer an explicit dispatcher-category; else keyword-match the description."""
    if fm:
        for k in ("dispatcher-category", "category"):
            if fm.get(k):
                return fm[k].strip().capitalize() + " (declared)"
    for label, rx in CATEGORY_KEYWORDS:
        if re.search(rx, blob, re.IGNORECASE):
            return label
    return "Uncategorized"


def load_trusted_authors(skill_root):
    """Load the trusted-author allowlist. Looks next to this script (bundled),
    so the runtime copy uses its own list, not one inside the skill under review."""
    path = Path(__file__).resolve().parent.parent / "references" / "trusted_authors.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data.get("trusted_authors", [])
    except Exception:
        return []


def resolve_author(author, trusted):
    """Match the declared author against the trusted allowlist (name/alias/github)."""
    a = (author or "").strip().lower()
    if not a:
        return None
    for entry in trusted:
        names = [entry.get("name", "")] + entry.get("aliases", [])
        gh = entry.get("github", "")
        if any(a == n.strip().lower() for n in names if n) or (gh and a in gh.lower()):
            return entry
    return None


def compute_score(metrics):
    """Apply the deduction model. Returns (score, breakdown, recommendation, forced_decline)."""
    score = 100
    breakdown = []
    for key, _pat, per, cap, label in SCORING_BUCKETS:
        n = metrics.get(key, 0)
        capped = min(n, cap)
        pen = capped * per
        if pen:
            note = f" (capped at {cap})" if n > cap else ""
            breakdown.append((label, n, -pen, note))
        score -= pen
    score = max(0, score)
    forced = []
    if metrics.get("hard_cred", 0) >= 1:
        forced.append("hard credential hit")
    if metrics.get("dangerous", 0) >= 8:
        forced.append("dangerous-call cap reached")
    if forced:
        rec = "Decline"
    elif score >= 90 and metrics.get("dangerous", 0) == 0 and metrics.get("network", 0) <= 6:
        rec = "No further review"
    elif score < 50:
        rec = "Decline"
    else:
        rec = "Further review recommended"
    return score, breakdown, rec, forced


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
            if val == "":
                # nested mapping (e.g. `metadata:`) — flatten its children into fm
                # so metadata.author / version / dispatcher-* become visible.
                i += 1
                while i < len(lines) and lines[i][:1].isspace() and ":" in lines[i] and not lines[i].lstrip().startswith("-"):
                    sk, _, sv = lines[i].partition(":")
                    fm.setdefault(sk.strip(), sv.strip().strip("\"'"))
                    i += 1
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
    ap.add_argument("--format", choices=("md", "html", "both"), default="md",
                    help="output format: md (default), html, or both. HTML uses assets/report-template.html")
    ap.add_argument("--profile", default=None,
                    help="path to a Phase-1 profile JSON (live author lookup + narrative): keys "
                         "summary, category, author_about, author_credibility, author_trust, author_links, other_notes")
    args = ap.parse_args()
    gate = load_scanner_gate(args.scanners)
    profile = {}
    if args.profile:
        try:
            profile = json.loads(Path(args.profile).read_text(encoding="utf-8"))
        except Exception:
            profile = {}
    trusted_authors = load_trusted_authors(None)

    root = Path(args.target).resolve()
    if not root.exists():
        sys.exit(f"Not found: {root}")
    files = [root] if root.is_file() else sorted(
        p for p in root.rglob("*") if p.is_file() and "node_modules" not in p.parts)
    base = root.parent if root.is_file() else root

    inventory, findings, domains, toolchain_hits = [], [], {}, []
    skill_md_text, fm = None, None
    scoring = {b[0]: 0 for b in SCORING_BUCKETS}  # dangerous/network/soft_cred/hard_cred/misplaced
    text_blob = []  # for category inference

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
            if ext in EXEC_EXT:  # score code files only; documented patterns don't inflate
                count_scoring_hits(text, scoring)
            if p.name in ("SKILL.md", "README.md") or ext == ".md":
                text_blob.append(text[:4000])
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

    # --- structural metrics + risk score (additive; never replaces the tier) ---
    name = (fm or {}).get("name", root.name)

    def _topdir(rel):
        parts = rel.replace("\\", "/").split("/")
        return parts[0] if len(parts) > 1 else ""

    def _is_script(rel):
        return Path(rel).suffix.lower() in EXEC_EXT

    subfolders = sorted({_topdir(i["rel"]) for i in inventory if _topdir(i["rel"])})
    metrics = {
        "subfolders": len(subfolders),
        "files": len(inventory),
        "skill_md": skill_md_text is not None,
        "assets_files": sum(1 for i in inventory if _topdir(i["rel"]) == "assets"),
        "reference_files": sum(1 for i in inventory if _topdir(i["rel"]) in ("references", "reference")),
        "scripts_files": sum(1 for i in inventory if _topdir(i["rel"]) == "scripts" and _is_script(i["rel"])),
        "total_scripts": sum(1 for i in inventory if _is_script(i["rel"])),
        "dangerous": scoring["dangerous"], "network": scoring["network"],
        "soft_cred": scoring["soft_cred"], "hard_cred": scoring["hard_cred"],
    }
    metrics["misplaced"] = sum(1 for i in inventory if _is_script(i["rel"])
                               and _topdir(i["rel"]) not in EXPECTED_SCRIPT_DIRS)
    scoring["misplaced"] = metrics["misplaced"]

    def _truthy(v):
        return str(v).strip().lower() in ("1", "true", "yes", "y", "on")
    writes_files = _truthy((fm or {}).get("dispatcher-writes-files", "")) if fm else False

    score, score_breakdown, recommendation, forced = compute_score(scoring)

    # author resolution (Phase 1 lookup feeds in via --profile for non-listed authors)
    author = (fm or {}).get("author", "")
    if not author and skill_md_text:
        m_a = re.search(r"\*\*Authors?:?\*\*\s*[:\-]?\s*([^|\n<]+)", skill_md_text)
        author = m_a.group(1).strip() if m_a else ""
    trusted_entry = resolve_author(author, trusted_authors)
    if trusted_entry:
        author_trust = trusted_entry.get("trust", "trusted")
        author_cred = trusted_entry.get("credibility", 90)
        author_about = trusted_entry.get("about", "")
        author_links = trusted_entry.get("links", [])
    else:
        author_trust = profile.get("author_trust", "unknown")
        author_cred = profile.get("author_credibility")
        author_about = profile.get("author_about", "")
        author_links = profile.get("author_links", [])

    blob = " ".join(text_blob) + " " + (fm or {}).get("description", "")
    category = profile.get("category") or infer_category(fm, blob)
    what_it_does = (fm or {}).get("description", "") or "(no frontmatter description)"

    other_notes = list(profile.get("other_notes", []))
    if writes_files:
        other_notes.append("Declares `dispatcher-writes-files: true` (writes to disk).")
    if any(_topdir(i["rel"]) == "tests" for i in inventory):
        other_notes.append("Ships a `tests/` folder.")
    if any("/.github/workflows/" in ("/" + i["rel"].replace("\\", "/") + "/") for i in inventory):
        other_notes.append("Ships CI (`.github/workflows`).")
    n_artifacts = sum(1 for i in inventory if _topdir(i["rel"]) in ("artifacts", "out", "output"))
    if n_artifacts > 20:
        other_notes.append(f"Ships {n_artifacts} generated artifact files (consider excluding from the installed copy).")

    # one/two paragraph synthesized summary of the report (override via --profile.summary)
    if profile.get("summary"):
        report_summary = profile["summary"]
    else:
        sev_bits = f"{len(crit)} critical, {len(warn)} warning, {len(info)} info finding(s)"
        risk_bits = (f"{metrics['dangerous']} dangerous call(s), {metrics['network']} network/tool call(s), "
                     f"{metrics['soft_cred']} soft- and {metrics['hard_cred']} hard-credential hit(s), "
                     f"{metrics['misplaced']} misplaced script(s)")
        report_summary = (
            f"`{name}` is a **{category}** skill — {what_it_does[:200]}. The external scanner gate returned "
            f"**{gate_verdict}** and static heuristics produced {sev_bits}; the suggested review tier is "
            f"**{tier}**. "
            f"The structural/risk scan found {risk_bits}, giving a heuristic risk score of **{score}/100** → "
            f"**{recommendation}**"
            + (f" (forced by {', '.join(forced)})" if forced else "")
            + f". Author is **{author or 'unknown'}** (trust: {author_trust}). This score is a mechanical aid, "
            "not a verdict — work the findings (§3), the OWASP map, and the reviewer judgement before approving.")

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
        rows = ["| OWASP | Risk | Static signal | Reviewer must still judge | Advice — what good looks like |",
                "|---|---|---|---|---|"]
        for asi_id, asi_name, cats, manual, advice in OWASP_ASI:
            hit = [c for c in cats if c in cats_fired]
            signal = ("⚠ " + ", ".join(sorted(set(hit)))) if hit else "clear"
            rows.append(f"| **{asi_id}** | {asi_name} | {signal} | {manual} | {advice} |")
        legend = ("\n_**⚠** = checked and a known risk pattern fired (see §3). **clear** = checked and no "
                  "known pattern matched — this is **not** proof of safety: the scan only catches known "
                  "patterns, so novel / obfuscated / intent-level risk can remain, and ASI06–ASI10 especially "
                  "need human judgement. ('clear' does not mean 'could not check' — every row is always "
                  "evaluated; skipped/missing external-scanner coverage is shown in §0.) Work the advice "
                  "column for every ⚠ row, and use it as a baseline checklist even where clear. Full taxonomy: "
                  "OWASP Top 10 for Agentic Applications v1.0 (2025-12-09) — see "
                  "references/owasp-top10-agent-skills.md._\n")
        return "\n".join(rows) + legend

    def build_html_report():
        """Render the same data as an HTML document using assets/report-template.html
        (skill-dispatcher 'warm paper' visual language). Reuses every computed value
        so the HTML and markdown reports never drift."""
        tmpl_path = Path(__file__).resolve().parent.parent / "assets" / "report-template.html"
        template = tmpl_path.read_text(encoding="utf-8")
        esc = html.escape
        cats_fired = {f["cat"] for f in findings}
        n_exec = sum(1 for i in inventory if i["kind"] == "executable")
        n_bin = sum(1 for i in inventory if i["kind"] == "binary/archive")

        def sev_badge(sev):
            return {SEV_CRIT: "crit", SEV_WARN: "warn", SEV_INFO: "info"}.get(sev, "info")

        def legend_dl(items):
            out = ["<dl class='legend'>"]
            for t, d in items:
                if t == "__grp__":
                    out.append(f"<div class='grp'>{esc(d)}</div>")
                else:
                    out.append(f"<dt>{esc(t)}</dt><dd>{esc(d)}</dd>")
            out.append("</dl>")
            return "".join(out)

        def section(num, title, body, legend=None):
            label = f'<span class="sec-num">§{num}.</span> ' if str(num).isdigit() else ''
            help_btn = ('<span class="help-btn" role="button" tabindex="0" title="Show legend" '
                        'aria-label="Show legend">?</span>') if legend else ''
            legend_box = f'<div class="info-box">{legend}</div>' if legend else ''
            return (f'<details class="section" open><summary>'
                    f'<span class="sec-h2">{label}{esc(title)}</span>{help_btn}'
                    f'<span class="chev" aria-hidden="true"></span></summary>'
                    f'{legend_box}{body}</details>')

        def finding_rows(fl):
            if not fl:
                return '<p class="empty">None detected.</p>'
            out = []
            for f in fl:
                ev = f' — <span class="ev">{esc(f["evidence"])}</span>' if f["evidence"] else ""
                out.append(
                    f'<div class="finding"><span class="badge {sev_badge(f["sev"])}">{esc(f["sev"])}</span> '
                    f'<span class="cat">{esc(f["cat"])}</span> — {esc(f["why"])}'
                    f'<div class="loc"><span class="ev">{esc(f["loc"])}</span>{ev}</div>'
                    f'<div class="judge">Reviewer judgement: ☐ confirmed ☐ false positive ☐ documented-not-performed</div></div>')
            return "".join(out)

        # --- stat cards ---
        if gate:
            gv = gate["gate"]
            gcls = {"BLOCK": "is-block", "PASS": "is-pass", "INCOMPLETE": "is-warn"}.get(gv, "")
            gsub = f'{gate["scanners_ran"]}/{gate["scanners_total"]} scanners ran'
        else:
            gv, gcls, gsub = "NOT RUN", "is-warn", "gate not run"
        tier_short = "REJECT" if "REJECT" in tier else next((f"Tier {n}" for n in "321" if n in tier), "Tier 0")

        def stat(label, value, sub, cls=""):
            return (f'<div class="stat-card {cls}"><span class="stat-label">{esc(label)}</span>'
                    f'<span class="stat-value">{esc(str(value))}</span>'
                    f'<span class="stat-sub">{esc(sub)}</span></div>')
        rec_cls = ("is-pass" if recommendation == "No further review"
                   else "is-block" if recommendation == "Decline" else "is-warn")
        stat_cards = "".join([
            stat("Scanner gate", gv, gsub, gcls),
            stat("Risk score", f"{score}/100", recommendation, rec_cls),
            stat("Critical", len(crit), "confirm or dismiss" if crit else "none detected", "is-block" if crit else ""),
            stat("Warnings", len(warn), "review each", "is-warn" if warn else ""),
            stat("Suggested tier", tier_short, tier_why[:60], "is-block" if "REJECT" in tier or "3" in tier else ""),
        ])

        # --- §0 gate ---
        if gate:
            rows = ['<table><thead><tr><th>Scanner</th><th>Status</th><th>Findings / score</th><th>Block?</th></tr></thead><tbody>']
            for r in gate["results"]:
                st = r["status"]
                if st == "ran":
                    sc = r.get("severity_counts", {})
                    sev = ", ".join(f"{k}:{v}" for k, v in sc.items() if v) or "none"
                    scorestr = f' · score {r["risk_score"]}' if r.get("risk_score") is not None else ""
                    retry = ' <span class="badge info">retried</span>' if r.get("retry") else ""
                    blk = '<span class="badge block">yes</span>' if r.get("block") else '<span class="badge pass">no</span>'
                    cell = f'<span class="badge {"block" if r.get("block") else "ran"}">ran</span>{retry}'
                    rows.append(f'<tr><td>{esc(r["name"])}</td><td>{cell}</td><td>{esc(sev)}{esc(scorestr)}</td><td>{blk}</td></tr>')
                elif st == "missing":
                    rows.append(f'<tr><td>{esc(r["name"])}</td><td><span class="badge missing">missing</span></td>'
                                f'<td>install: <code>{esc(r.get("install_hint",""))}</code></td><td>—</td></tr>')
                elif st == "skipped":
                    rows.append(f'<tr><td>{esc(r["name"])}</td><td><span class="badge skipped">skipped</span></td>'
                                f'<td>{esc(r.get("skip_reason",""))}</td><td>—</td></tr>')
                else:
                    rows.append(f'<tr><td>{esc(r["name"])}</td><td><span class="badge warn">error</span></td>'
                                f'<td><code>{esc(str(r.get("error",""))[:120])}</code></td><td>—</td></tr>')
            rows.append("</tbody></table>")
            retry_notes = [f'<li><em>{esc(r["name"])}</em> — {esc(r["retry_note"])}</li>'
                           for r in gate["results"] if r.get("retry_note")]
            if retry_notes:
                rows.append('<p class="note"><strong>Retries:</strong></p><ul>' + "".join(retry_notes) + "</ul>")
            gate_body = "".join(rows)
        else:
            gate_body = ('<p class="note"><strong>Gate not run.</strong> Run '
                         '<code>run_scanners.py &lt;target&gt; -o scanner_results.json</code> and re-run with '
                         '<code>--scanners scanner_results.json</code>. Tier 1+ approval requires it.</p>')

        # --- §1 identity ---
        ident = (f'<dl class="kv">'
                 f'<dt>Skill name</dt><dd>{esc(name)}</dd>'
                 f'<dt>Path scanned</dt><dd><code>{esc(str(root))}</code></dd>'
                 f'<dt>Files</dt><dd>{len(inventory)} ({n_exec} executable, {n_bin} binary/archive)</dd>'
                 f'<dt>Description</dt><dd>{esc((fm or {}).get("description", "(none)")[:400])}</dd>'
                 f'<dt>Version / commit pinned</dt><dd><em>(reviewer: fill in exact hash)</em></dd>'
                 f'<dt>Source classification</dt><dd>☐ Internal ☐ Verified vendor ☐ Known community ☐ Unknown</dd></dl>')

        # --- §2 inventory (collapsed) ---
        inv_rows = "".join(
            f'<tr><td><code>{esc(i["rel"])}</code></td><td>{esc(i["kind"])}</td><td>{i["size"]}</td>'
            f'<td><code>{esc(i["hash"])}</code></td><td>{"yes" if i["hidden"] else ""}</td></tr>' for i in inventory)
        inv_body = (f'<details><summary>{len(inventory)} files — click to expand</summary>'
                    f'<table><thead><tr><th>File</th><th>Kind</th><th>Size</th><th>SHA-256 (16)</th><th>Hidden</th></tr></thead>'
                    f'<tbody>{inv_rows}</tbody></table></details>')

        # --- §3 findings ---
        find_body = (f'<h3>Critical ({len(crit)})</h3>{finding_rows(crit)}'
                     f'<h3>Warnings ({len(warn)})</h3>{finding_rows(warn)}'
                     f'<h3>Info ({len(info)})</h3>{finding_rows(info)}')
        if domains:
            dom_items = []
            for d, c in sorted(domains.items()):
                tag = ' <span class="badge warn">not allowlisted</span>' if d in unknown_domains else ''
                dom_items.append(f'<li><code>{esc(d)}</code> ({c}×){tag}</li>')
            find_body += f'<h3>External domains referenced</h3><ul>{"".join(dom_items)}</ul>'

        # --- §4 OWASP ---
        owasp = ['<table><thead><tr><th>OWASP</th><th>Risk</th><th>Static signal</th>'
                 '<th>Reviewer must still judge</th><th>Advice — what good looks like</th></tr></thead><tbody>']
        for asi_id, asi_name, cats, manual, advice in OWASP_ASI:
            hit = sorted({c for c in cats if c in cats_fired})
            sig = (f'<span class="badge warn">⚠ {esc(", ".join(hit))}</span>' if hit
                   else '<span class="badge clear">clear</span>')
            owasp.append(f'<tr><td><strong>{asi_id}</strong></td><td>{esc(asi_name)}</td><td>{sig}</td>'
                         f'<td>{esc(manual)}</td><td>{esc(advice)}</td></tr>')
        owasp.append('</tbody></table><p class="note">⚠ = a heuristic in this category fired; "clear" = no pattern '
                     'matched, which is <strong>not</strong> proof of safety. Work the advice column for every ⚠ row. '
                     'Full taxonomy: OWASP Top 10 for Agentic Applications v1.0 (2025-12-09).</p>')
        owasp_body = "".join(owasp)

        # --- §5 checklist ---
        def chk(cond_block, label):
            if cond_block == "block":
                return f'<li><span class="mark flag">⚠ BLOCK</span> {esc(label)}</li>'
            if cond_block == "flag":
                return f'<li><span class="mark flag">⚠ check</span> {esc(label)}</li>'
            if cond_block == "ok":
                return f'<li><span class="mark ok">✓</span> {esc(label)}</li>'
            return f'<li><span class="mark todo">☐</span> {esc(label)}</li>'
        gate_chk = "block" if gate_verdict == "BLOCK" else ("flag" if gate_verdict == "INCOMPLETE"
                   else ("ok" if gate_verdict in ("PASS",) else "todo"))
        checklist = "<ul class='checklist'>" + "".join([
            chk("flag" if any(f["cat"] == "Obfuscation" for f in findings) else "todo", "Obfuscated/encoded payloads"),
            chk("flag" if any(f["cat"] == "Runtime download+exec" for f in findings) else "todo", "Runtime download & execute"),
            chk("flag" if any(f["cat"] in ("Credential access", "Hardcoded secret") for f in findings) else "todo", "Credential/secret access"),
            chk("flag" if any(f["cat"] in ("Concealment", "Injection/override", "Hidden content") for f in findings) else "todo", "Concealment / instruction override / hidden content"),
            chk("flag" if any(f["cat"] in ("Persistence", "Agent-config tampering") for f in findings) else "todo", "Persistence outside skill directory"),
            chk("todo", "Description vs. actual behaviour mismatch (manual)"),
            chk("flag" if toolchain_hits else "todo", "Toolchain auto-executed side files"),
            chk("flag" if unknown_domains else "todo", "Unexplained hardcoded URLs/domains"),
            chk("todo", "Publisher impersonation (manual)"),
            chk("flag" if any(f["cat"] == "Authority claim" for f in findings) else "todo", "Pressure/authority framing"),
            chk(gate_chk, "External scanner gate (§0) clean"),
        ]) + "</ul>"

        # --- §6 tier ---
        tier_body = (f'<p><span class="badge {"block" if "REJECT" in tier or "3" in tier else "warn"}">{esc(tier)}</span> — {esc(tier_why)}.</p>'
                     f'<p class="note">Adjust for source (verified vendor may lower one tier) and blast radius '
                     f'(credentials / sensitive data / org-wide rollout forces Tier 3). Gate state: '
                     f'<strong>{esc(gate_verdict)}</strong> — a BLOCK forces reject/escalate; INCOMPLETE blocks Tier 1+ '
                     f'until a scanner runs.</p>')

        # --- §7+§8 reviewer + sign-off ---
        judge_body = (
            '<ul class="checklist">'
            f'<li><span class="mark todo">☐</span> External scanner gate reviewed (§0) — verdict: {esc(gate_verdict)}</li>'
            '<li><span class="mark todo">☐</span> Description alignment verified — notes: ____</li>'
            '<li><span class="mark todo">☐</span> All flagged locations read in full</li>'
            '<li><span class="mark todo">☐</span> OWASP coverage map (§4) walked, each ⚠ resolved</li>'
            '<li><span class="mark todo">☐</span> Sandbox behavioural test performed (Tier 2+) — observations: ____</li>'
            '<li><span class="mark todo">☐</span> Final tier: ____ · Final verdict: ☐ Approve ☐ Approve with conditions ☐ Escalate ☐ Reject</li>'
            '</ul>'
            '<table><thead><tr><th>Role</th><th>Name</th><th>Date</th></tr></thead><tbody>'
            '<tr><td>Reviewer</td><td></td><td></td></tr>'
            '<tr><td>Second reviewer (Tier 2+)</td><td></td><td></td></tr>'
            '<tr><td>Security team (Tier 3)</td><td></td><td></td></tr></tbody></table>'
            '<p class="note">Re-review due: ____ (or on any version change).</p>')

        # --- Profile & summary ---
        cred_txt = f"{author_cred} / 100" if author_cred is not None else "unknown"
        about_txt = author_about or "(unknown — run Phase 1 author lookup, or add to references/trusted_authors.json)"
        links_txt = ", ".join(esc(l) for l in author_links) if author_links else "—"
        notes_html = ("<ul>" + "".join(f"<li>{esc(n)}</li>" for n in other_notes) + "</ul>") if other_notes else '<p class="note">None noted.</p>'
        trust_badge = {"trusted": "pass", "assessed": "warn", "flagged": "block"}.get(str(author_trust).lower(), "info")
        profile_body = (
            f'<p>{esc(report_summary)}</p>'
            '<dl class="kv">'
            f'<dt>Category</dt><dd>{esc(category)}</dd>'
            f'<dt>What it does</dt><dd>{esc(what_it_does[:300])}</dd>'
            f'<dt>Author</dt><dd>{esc(author or "unknown")}</dd>'
            f'<dt>Author trust</dt><dd><span class="badge {trust_badge}">{esc(str(author_trust))}</span></dd>'
            f'<dt>Author credibility</dt><dd>{esc(cred_txt)}</dd>'
            f'<dt>About the author</dt><dd>{esc(about_txt)}</dd>'
            f'<dt>Links</dt><dd>{links_txt}</dd>'
            '</dl><p class="note"><strong>Other useful things to know</strong></p>' + notes_html)

        # --- Metrics & risk score ---
        rec_badge = ("pass" if recommendation == "No further review"
                     else "block" if recommendation == "Decline" else "warn")
        forced_html = f' <span class="badge block">forced by {esc(", ".join(forced))}</span>' if forced else ""
        mrows = "".join(f'<tr><td>{esc(lbl)}</td><td>{v}</td></tr>' for lbl, v in [
            ("Subfolders", metrics["subfolders"]), ("Files", metrics["files"]),
            ("SKILL.md present", "Yes" if metrics["skill_md"] else "No"),
            ("Assets files", metrics["assets_files"]), ("References files", metrics["reference_files"]),
            ("Scripts files (in scripts/)", metrics["scripts_files"]), ("Total script files", metrics["total_scripts"]),
            ("Misplaced scripts", metrics["misplaced"]), ("Dangerous calls", metrics["dangerous"]),
            ("Network/tool calls", metrics["network"]), ("Soft credential hits", metrics["soft_cred"]),
            ("Hard credential hits", metrics["hard_cred"]), ("Writes files (declared)", "Yes" if writes_files else "No")])
        bd_html = ("".join(f'<li>{esc(lbl)}: {n} hit(s) → {pen}{esc(note)}</li>' for lbl, n, pen, note in score_breakdown)
                   or "<li>No penalties.</li>")
        metrics_body = (
            f'<p><span class="badge {rec_badge}">{score}/100 → {esc(recommendation)}</span>{forced_html}</p>'
            f'<table><thead><tr><th>Metric</th><th>Value</th></tr></thead><tbody>{mrows}</tbody></table>'
            f'<p class="note"><strong>Score breakdown (base 100):</strong></p><ul>{bd_html}</ul>'
            '<p class="note">Penalties: misplaced −5 (cap 4), dangerous −8 (cap 8 → forces Decline), network −2 '
            '(cap 12), soft-cred −5 (cap 4), hard-cred −40 (any hit forces Decline). Counted in code files only, '
            'so behaviour merely documented in markdown does not inflate the score. Complements — never replaces — '
            'the gate (§0) and tier (§6).</p>')

        gate_legend = legend_dl([
            ("__grp__", "Gate verdict"),
            ("PASS", "At least one scanner ran and none returned a blocking result."),
            ("BLOCK", "A scanner flagged high/critical (or score >=51 / 'do not install') — do not approve."),
            ("INCOMPLETE", "No scanner ran. Tier 1+ approval needs at least one, or a documented exception."),
            ("__grp__", "Per-scanner status"),
            ("ran", "The scanner executed and returned results."),
            ("ran (retried)", "Re-run against a copy with frontmatter control chars sanitized; not byte-identical to the original."),
            ("skipped", "Installed but not run (e.g. Snyk without SNYK_TOKEN)."),
            ("missing", "Not installed; the install command is shown."),
            ("error", "The tool failed to produce a result (auth/config/crash)."),
        ])
        findings_legend = legend_dl([
            ("Critical", "A pattern that may be performing a risky behaviour — confirm or dismiss before approval."),
            ("Warning", "Worth a look; frequently a false positive in security/testing skills."),
            ("Info", "Low-signal context."),
            ("documented-not-performed", "The risky pattern is described/detected in text, not actually executed — a common dismissal."),
        ])
        owasp_legend = legend_dl([
            ("__grp__", "Signal column"),
            ("clear", "Checked: the pattern scan ran for this category and matched no known risk pattern. "
                      "NOT a guarantee of safety — it only catches known patterns, so novel / obfuscated / "
                      "intent-level risk can remain, and ASI06-ASI10 especially need human judgement. "
                      "(It does not mean 'could not check'; every row is always evaluated. Skipped or "
                      "missing external-scanner coverage is shown in the gate, section 0.)"),
            ("⚠", "Checked: a known risk pattern in this category fired — see the Findings pane (section 3)."),
            ("__grp__", "Finding categories you may see"),
            ("External domains", "A non-allowlisted URL/domain is referenced."),
            ("Exfiltration channel", "A known callback/exfil sink (webhook, ngrok, paste-bin, ...)."),
            ("Network call", "An outbound HTTP/socket/fetch call."),
            ("Dynamic execution", "eval/exec/subprocess/shell-out — runs code or commands."),
            ("Runtime download+exec", "Downloads and runs code (e.g. curl piped into a shell)."),
            ("Obfuscation", "base64/hex/very-long-line content that hides intent."),
            ("Credential access", "Reads env secrets, ~/.ssh, ~/.aws, keychains, etc."),
            ("Hardcoded secret", "A literal API key/token/password embedded in a file."),
            ("Persistence", "Writes to shell profiles, cron, services."),
            ("Agent-config tampering", "Edits CLAUDE.md/AGENTS.md/settings/memory — outlives the skill."),
            ("Concealment / Authority claim", "Hides actions from the user / claims pre-authorization."),
            ("Toolchain auto-execution", "Side files run by tests/CI/hooks/installers."),
        ])
        metrics_legend = legend_dl([
            ("__grp__", "Recommendation"),
            ("No further review", "Score >=90, no dangerous calls, <=6 network calls."),
            ("Further review recommended", "Middle ground — a human should look."),
            ("Decline", "Forced by any hard-credential hit or the dangerous-call cap, or score <50."),
            ("__grp__", "Counts (code files only)"),
            ("Misplaced scripts", "Executable files outside scripts/ or tests/ (-5 each, cap 4)."),
            ("Dangerous calls", "eval/exec/subprocess/rm-rf/deserialization (-8 each, cap 8 -> Decline)."),
            ("Network/tool calls", "HTTP/socket/fetch/CLI network calls (-2 each, cap 12)."),
            ("Soft credential hits", "References to api_key/token/password/secret, env reads (-5 each, cap 4)."),
            ("Hard credential hits", "Literal secrets (keys/tokens/JWT/PEM) (-40 each, any -> Decline)."),
            ("Writes files", "Declared via metadata.dispatcher-writes-files (informational)."),
        ])
        tier_legend = legend_dl([
            ("Tier 0", "Instructions-only, negligible blast radius."),
            ("Tier 1", "Low risk — pin version + register."),
            ("Tier 2", "Executable content with warnings — sandbox test + second reviewer."),
            ("Tier 3", "Critical findings, binaries, or a BLOCK gate — security team."),
            ("REJECT", "Confirmed concealment/exfiltration or BLOCK — reject + quarantine."),
        ])
        profile_legend = legend_dl([
            ("__grp__", "Author trust"),
            ("trusted", "On the references/trusted_authors.json allowlist — vouched for."),
            ("assessed", "Not listed; rated from a Phase-1 live lookup (--profile)."),
            ("unknown", "Not listed and no lookup provided — treat with caution."),
            ("flagged", "Known-problematic."),
            ("__grp__", "Other"),
            ("Credibility", "0-100 confidence in the author (from the allowlist or the lookup)."),
            ("Category", "From the skill's dispatcher-category, else inferred from the description."),
        ])

        sections = "".join([
            section("", "Profile & summary", profile_body, profile_legend),
            section("0", "External scanner gate (mandatory for Tier 1+)", gate_body, gate_legend),
            section("1", "Identity", ident),
            section("2", "File inventory", inv_body),
            section("3", "Findings", find_body, findings_legend),
            section("4", "OWASP Top 10 for Agentic Applications — coverage map", owasp_body, owasp_legend),
            section("", "Metrics & risk score", metrics_body, metrics_legend),
            section("5", "Red-flag checklist", checklist),
            section("6", "Suggested review tier", tier_body, tier_legend),
            section("7", "Reviewer judgement & sign-off", judge_body),
        ])
        gen = (f'<span>Generated {date.today().isoformat()}</span>'
               f'<span>Static heuristics + external scanner gate</span>'
               f'<span>Gate: {esc(gate_verdict)}</span>')
        return (template.replace("{{TITLE}}", esc(name))
                .replace("{{GENERATED_LINE}}", gen)
                .replace("{{STAT_CARDS}}", stat_cards)
                .replace("{{SECTIONS}}", sections))

    def build_profile_md():
        links = ", ".join(author_links) if author_links else "—"
        about = author_about or "_(unknown — run Phase 1 author lookup, or add the author to references/trusted_authors.json)_"
        notes = "".join(f"- {n}\n" for n in other_notes) or "- _None noted._\n"
        cred = f"{author_cred} / 100" if author_cred is not None else "_unknown_"
        return f"""## Profile & summary

{report_summary}

| Field | Value |
|---|---|
| Category | {category} |
| What it does | {what_it_does[:300]} |
| Author | {author or '_unknown_'} |
| Author trust | **{author_trust}** |
| Author credibility | {cred} |
| About the author | {about} |
| Links | {links} |

**Other useful things to know**
{notes}
"""

    def build_metrics_md():
        forced_note = f" — **forced by {', '.join(forced)}**" if forced else ""
        bd = "".join(f"- {lbl}: {n} hit(s) → {pen}{note}\n" for lbl, n, pen, note in score_breakdown) or "- _No penalties._\n"
        yn = lambda b: "Yes" if b else "No"
        return f"""## Metrics & risk score

**Heuristic risk score: {score} / 100 → {recommendation}**{forced_note}

| Metric | Value |
|---|---|
| Subfolders | {metrics['subfolders']} |
| Files | {metrics['files']} |
| SKILL.md present | {yn(metrics['skill_md'])} |
| Assets files | {metrics['assets_files']} |
| References files | {metrics['reference_files']} |
| Scripts files (in `scripts/`) | {metrics['scripts_files']} |
| Total script files | {metrics['total_scripts']} |
| Misplaced scripts | {metrics['misplaced']} |
| Dangerous calls | {metrics['dangerous']} |
| Network/tool calls | {metrics['network']} |
| Soft credential hits | {metrics['soft_cred']} |
| Hard credential hits | {metrics['hard_cred']} |
| Writes files (declared) | {yn(writes_files)} |

Score breakdown (base 100):
{bd}
> Penalties: misplaced −5 (cap 4), dangerous −8 (cap 8 → forces Decline), network −2 (cap 12),
> soft-cred −5 (cap 4), hard-cred −40 (any hit forces Decline). Counted in code files only, so
> behaviour merely *documented* in markdown does not inflate the score. This score is a mechanical
> aid that complements — never replaces — the gate (§0) and tier (§6).
"""

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

{build_profile_md()}
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
{build_metrics_md()}
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
    out = Path(args.output)
    stem = out.with_suffix("")
    written = {}
    if args.format in ("md", "both"):
        md_path = out if out.suffix.lower() != ".html" else stem.with_suffix(".md")
        Path(md_path).write_text(report, encoding="utf-8")
        written["markdown"] = str(md_path)
    if args.format in ("html", "both"):
        html_path = out if out.suffix.lower() == ".html" else stem.with_suffix(".html")
        Path(html_path).write_text(build_html_report(), encoding="utf-8")
        written["html"] = str(html_path)
    print(json.dumps({"files": len(inventory), "critical": len(crit), "warnings": len(warn),
                      "info": len(info), "suggested_tier": tier, "scanner_gate": gate_verdict,
                      "outputs": written}))


if __name__ == "__main__":
    main()
