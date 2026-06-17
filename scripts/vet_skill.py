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
    (r"(?:api[_-]?key|token|secret|password)\s*[:=]\s*['\"]([A-Za-z0-9_\-]{16,})['\"]", SEV_CRIT, "Hardcoded secret", "Possible hardcoded credential"),
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
                     "skills.sh", "npmjs.com", "pypi.org", "owasp.org",
                     "img.shields.io", "buymeacoffee.com"}
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
    re.compile(r"(?:api[_-]?key|token|secret|password|passwd|client[_-]?secret)\s*[:=]\s*['\"]([A-Za-z0-9_\-/+=]{16,})['\"]", re.IGNORECASE),
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
BUCKET_LABELS = {key: label for key, _pat, _per, _cap, label in SCORING_BUCKETS}
EXPECTED_SCRIPT_DIRS = {"scripts", "tests"}  # code here is expected; elsewhere = misplaced

# Buckets where a hit found only in test-path code doesn't represent a
# capability of the skill itself: deleting the tests would not reduce what an
# agent loading the skill can do. Hard-credential hits are excluded - a real
# secret committed to a test fixture is still a real secret regardless of
# where it lives.
TEST_SPLIT_BUCKETS = {"dangerous", "network", "soft_cred"}

# Matches files that are test-only surface: under a tests/__tests__/spec
# directory, or named like a JS/TS or Python test file.
TEST_PATH_RX = re.compile(
    r"(^|[/\\])(tests?|__tests__|spec)[/\\]"
    r"|\.(test|spec)\.(ts|tsx|js|jsx|mjs|cjs)$"
    r"|(^|[/\\])conftest\.py$|_test\.py$|(^|[/\\])test_.*\.py$",
    re.IGNORECASE,
)


def is_test_path(rel: str) -> bool:
    """True if `rel` is test-only code - patterns found here are reported
    separately and don't affect the heuristic score (see TEST_SPLIT_BUCKETS)."""
    return bool(TEST_PATH_RX.search(rel.replace("\\", "/")))


# Files an installed skill does not need to do its job. Deleting them before
# install removes whatever findings they carry without reducing what the skill
# can do at runtime - so a reviewer can clear "noise" flags by shipping a
# trimmed copy. SKILL.md, scripts/, references/, assets/ and LICENSE are always
# treated as essential and never appear here.
REMOVABLE_CLASSES = [
    ("test",    TEST_PATH_RX),
    ("backup",  re.compile(r"\.(bak|orig|old|tmp|swp|swo)$|~$", re.IGNORECASE)),
    ("docs",    re.compile(r"(^|[/\\])(README|CHANGELOG|CONTRIBUTING|CODE_OF_CONDUCT|"
                           r"SECURITY|HISTORY|AUTHORS|NOTICE|TODO|ROADMAP)(\.[A-Za-z0-9]+)?$",
                           re.IGNORECASE)),
    ("example", re.compile(r"(^|[/\\])(examples?|fixtures?|samples?|demos?|mocks?|__mocks__)([/\\]|$)",
                           re.IGNORECASE)),
    ("ci",      re.compile(r"(^|[/\\])\.github([/\\]|$)|(^|[/\\])\.gitlab-ci\.ya?ml$"
                           r"|(^|[/\\])\.circleci([/\\]|$)|(^|[/\\])azure-pipelines\.ya?ml$"
                           r"|(^|[/\\])\.travis\.ya?ml$|(^|[/\\])appveyor\.ya?ml$", re.IGNORECASE)),
    ("config",  re.compile(r"(^|[/\\])(\.gitignore|\.gitattributes|\.editorconfig|\.npmignore|"
                           r"\.eslintrc[^/\\]*|\.prettier[^/\\]*|tsconfig[^/\\]*\.json|"
                           r"jest\.config\.[A-Za-z]+|vitest\.config\.[A-Za-z]+|"
                           r"\.pre-commit-config\.ya?ml)$", re.IGNORECASE)),
]
REMOVABLE_REASON = {
    "test":    "test file — not loaded at runtime",
    "backup":  "backup/scratch leftover — safe to drop",
    "docs":    "human documentation — not loaded by the agent",
    "example": "example/fixture content — not part of the runtime",
    "ci":      "CI/automation config — only runs in the repo",
    "config":  "dev tooling config — lint/build only",
    "mixed":   "removable files",
}
ESSENTIAL_BASENAMES = {"SKILL.md", "LICENSE", "LICENSE.md", "LICENSE.txt"}


def classify_removable(rel: str):
    """Return (reason_key, human_reason) if the installed skill does not need
    `rel` at runtime, else (None, None)."""
    r = rel.replace("\\", "/")
    base = r.rsplit("/", 1)[-1]
    if base in ESSENTIAL_BASENAMES:
        return (None, None)
    for key, rx in REMOVABLE_CLASSES:
        if rx.search(r):
            return (key, REMOVABLE_REASON[key])
    return (None, None)


def finding_file(loc):
    """Best-effort source file for a finding from its `loc` (e.g. 'tests/x.js:4'
    -> 'tests/x.js'). Returns None for aggregate ('-') or absolute-path locs."""
    if not loc or loc == "-":
        return None
    s = loc.replace("\\", "/")
    s = re.sub(r":\d+$", "", s)            # strip trailing :line
    if re.match(r"^[A-Za-z]:/", s) or s.startswith("/"):
        return None                        # absolute path = root-level meta finding
    return s


# --- reviewer inventory: what the skill reaches, runs, downloads, installs ----
# Descriptive aggregation only; NEVER scored. Surfaces observable references so a
# human reviewer can see, at a glance, the skill's outward surface. Imports/exec/
# env/filesystem/dynamic patterns are read from code files only; installs and
# downloads are read from every text file (they are meaningful as documented
# instructions in a README, too). Domains are aggregated separately (URL_RE).
PY_STDLIB = getattr(sys, "stdlib_module_names", frozenset())
NODE_BUILTINS = {"assert", "buffer", "child_process", "cluster", "console", "crypto",
    "dgram", "dns", "events", "fs", "http", "http2", "https", "net", "os", "path",
    "perf_hooks", "process", "querystring", "readline", "stream", "string_decoder",
    "timers", "tls", "tty", "url", "util", "v8", "vm", "worker_threads", "zlib"}
JS_EXT = {".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs"}

INV_IMPORT_PY = re.compile(r"^\s*(?:import\s+([A-Za-z_][\w.]*)|from\s+([A-Za-z_][\w.]*)\s+import)", re.M)
INV_IMPORT_JS = re.compile(r"""require\(\s*['"]([^'"]+)['"]\s*\)|import\b[^;\n]*?from\s*['"]([^'"]+)['"]""")
INV_EXEC_MECH = re.compile(
    r"(subprocess\.(?:run|call|Popen|check_output|check_call)|os\.system|os\.popen"
    r"|child_process|execSync|spawnSync|Start-Process|Invoke-Expression)")
INV_TOOLS = re.compile(
    r"(?<!``)"                       # skip ```bash / ```python markdown fence language tags
    r"""(?:^|[\s'"`\[(;&|>])"""
    r"(git|gh|npm|npx|yarn|pnpm|pip3?|python3?|node|deno|bun|docker-compose|docker"
    r"|kubectl|curl|wget|bash|pwsh|powershell|cmd|cargo|gem|brew|apt-get|apt|choco"
    r"|winget|dotnet|uvx|uv|ssh|scp|rsync|tar|unzip|openssl|aws|gcloud|terraform)"
    r"""(?=[\s'"`\\/]|$)""", re.M)
INV_DOWNLOAD = re.compile(
    r"""(curl|wget|Invoke-WebRequest|\biwr\b|urlretrieve|urlopen|requests\.get"""
    r"""|http\.client|fetch\(|git\s+clone|pip\s+download)"""
    r"""|(https?://[^\s'"]+\.(?:zip|tar\.gz|tgz|whl|exe|msi|deb|rpm|dmg|pkg|jar))""")
INV_INSTALL = re.compile(
    r"((?:pip3?|python3?\s+-m\s+pip|uv\s+pip|pipx)\s+install|uvx|npm\s+(?:install|i|add)"
    r"|yarn\s+add|pnpm\s+add|npx|(?:apt-get|apt)\s+install|brew\s+install|cargo\s+install"
    r"|go\s+(?:install|get)|gem\s+install|choco\s+install|winget\s+install|dotnet\s+add"
    r"|conda\s+install)")
INV_ENV = re.compile(
    r"""os\.environ\.get\(\s*['"]([^'"]+)['"]|os\.environ\[\s*['"]([^'"]+)['"]\]"""
    r"""|os\.getenv\(\s*['"]([^'"]+)['"]|process\.env\.([A-Za-z_]\w*)"""
    r"""|process\.env\[\s*['"]([^'"]+)['"]\]|\$env:([A-Za-z_]\w*)""")
INV_FSWRITE = re.compile(
    r"""(open\([^)]*,\s*['"][^'"]*[wax+][^'"]*['"]|\.write_text|\.write_bytes"""
    r"""|\.writeFileSync|\.writeFile|fs\.write|shutil\.(?:copy\w*|move)|os\.makedirs"""
    r"""|os\.mkdir|Out-File|Set-Content)""")
INV_FSDELETE = re.compile(
    r"(os\.remove|os\.unlink|os\.rmdir|shutil\.rmtree|fs\.unlink|fs\.rm\b"
    r"|Remove-Item|\brm\s+-[rfRF]+)")
INV_DYNAMIC = re.compile(
    r"(\beval\(|\bexec\(|new\s+Function\(|\bFunction\(|pickle\.loads|marshal\.loads|\bcompile\()")
INV_ENDPOINT = re.compile(r"""https?://[^\s'"`)>\]}]+""")
INV_LISTENER = re.compile(
    r"(socket\.bind|\.listen\(|createServer|app\.run\(|uvicorn\.run|HTTPServer"
    r"|http\.server|server\.bind|EXPOSE\s+\d+)")
INV_PERSIST = re.compile(
    r"(CLAUDE\.md|AGENTS?\.md|\.bashrc|\.zshrc|\.bash_profile|\.profile|crontab|/etc/cron"
    r"|/etc/hosts|/etc/systemd|systemctl|launchctl|settings\.json|\.claude\b|\.gitconfig"
    r"|~/\.aws|~/\.ssh|\.ssh/|authorized_keys|known_hosts)")

# (key, section title) — render order for the inventory section.
INVENTORY_SECTIONS = [
    ("exec",     "Process & shell execution sites"),
    ("tool",     "External CLI tools"),
    ("library",  "Libraries / imports"),
    ("endpoint", "Outbound URLs / endpoints (non-allowlisted hosts)"),
    ("listener", "Network listeners / servers"),
    ("download", "Downloads"),
    ("install",  "Installs"),
    ("env",      "Environment variables / secrets read"),
    ("persist",  "Agent-config / persistence targets touched"),
    ("fswrite",  "Files written / created"),
    ("fsdelete", "Files or directories deleted"),
    ("dynamic",  "Dynamic code execution"),
]


def _inv_line(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


def _allowlisted_host(host: str) -> bool:
    host = host.lower()
    return any(host == a or host.endswith("." + a) for a in ALLOWLIST_DOMAINS)


def extract_inventory(rel: str, ext: str, text: str):
    """Yield (category, token, line, extra) tuples for the reviewer inventory."""
    out = []
    # installs / downloads / named tools / endpoints / listeners / persistence —
    # meaningful in docs and code alike (the doc-vs-code context is marked later).
    for m in INV_INSTALL.finditer(text):
        out.append(("install", re.sub(r"\s+", " ", m.group(1)).strip().lower(), _inv_line(text, m.start()), None))
    for m in INV_DOWNLOAD.finditer(text):
        tok = m.group(1) or m.group(2) or m.group(0)
        out.append(("download", re.sub(r"\s+", " ", tok).strip(), _inv_line(text, m.start()), None))
    for m in INV_TOOLS.finditer(text):
        out.append(("tool", m.group(1).lower(), _inv_line(text, m.start()), None))
    for m in INV_ENDPOINT.finditer(text):
        url = m.group(0).rstrip(".,);")
        host = re.sub(r"^https?://", "", url).split("/")[0].split(":")[0].replace("\\", "")
        if "." in host and not _allowlisted_host(host):  # skip regex-literal / non-host noise
            out.append(("endpoint", url[:80], _inv_line(text, m.start()), None))
    for m in INV_LISTENER.finditer(text):
        out.append(("listener", m.group(1).split("(")[0].strip(), _inv_line(text, m.start()), None))
    for m in INV_PERSIST.finditer(text):
        out.append(("persist", m.group(1).strip(), _inv_line(text, m.start()), None))
    if ext not in EXEC_EXT:
        return out
    # imports (code only)
    if ext == ".py":
        for m in INV_IMPORT_PY.finditer(text):
            mod = (m.group(1) or m.group(2) or "").split(".")[0]
            if mod:
                out.append(("library", mod, _inv_line(text, m.start()),
                            "stdlib" if mod in PY_STDLIB else "third-party"))
    elif ext in JS_EXT:
        for m in INV_IMPORT_JS.finditer(text):
            spec = m.group(1) or m.group(2) or ""
            if not spec or spec[0] in "./":
                continue
            if spec.startswith("@"):
                pkg = "/".join(spec.split("/")[:2])
            else:
                pkg = spec.split("/")[0]
            bare = pkg[5:] if pkg.startswith("node:") else pkg
            out.append(("library", pkg, _inv_line(text, m.start()),
                        "builtin" if (pkg.startswith("node:") or bare in NODE_BUILTINS) else "third-party"))
    # process/shell execution sites (code only)
    for m in INV_EXEC_MECH.finditer(text):
        out.append(("exec", m.group(1), _inv_line(text, m.start()), None))
    # env vars / secrets read
    for m in INV_ENV.finditer(text):
        var = next((g for g in m.groups() if g), None)
        out.append(("env", var or "(dynamic)", _inv_line(text, m.start()), None))
    # filesystem writes / deletes
    for m in INV_FSWRITE.finditer(text):
        out.append(("fswrite", m.group(1).split("(")[0].strip(), _inv_line(text, m.start()), None))
    for m in INV_FSDELETE.finditer(text):
        out.append(("fsdelete", m.group(1).strip(), _inv_line(text, m.start()), None))
    # dynamic code execution
    for m in INV_DYNAMIC.finditer(text):
        out.append(("dynamic", m.group(1).split("(")[0].strip(), _inv_line(text, m.start()), None))
    return out


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


# Common placeholder/example markers seen in .env.example, docs, and demo code.
# A match here is still flagged and still requires manual verification - it only
# adds a hint so a reviewer isn't left re-deriving "this is obviously a sample"
# by hand for every one of dozens of hits.
PLACEHOLDER_MARKERS_RX = re.compile(
    r"change[-_]?(this|me)\b"
    r"|your[-_].*(key|token|secret|password|here)"
    r"|\b(sample|dummy|placeholder|example|fake|notreal|not[-_]a[-_]real|redacted|lorem|insert|replace|todo|fixme)\b"
    r"|x{4,}|\*{4,}|0{8,}|1{8,}"
    r"|\$\{|\{\{|<[a-z0-9_-]+>|%[a-z0-9_-]+%",
    re.IGNORECASE,
)
# A value that is just a few dictionary-style words joined by separators (e.g.
# "super-secret-key-change-this-in-production") reads as prose, not a real key.
READABLE_PHRASE_RX = re.compile(r"^[a-zA-Z]+(?:[-_][a-zA-Z]+){2,}$")


def is_placeholder_value(value: str) -> bool:
    """Heuristic only - a True still gets flagged in the report, never auto-dismissed."""
    v = (value or "").strip().strip("'\"")
    return bool(PLACEHOLDER_MARKERS_RX.search(v) or READABLE_PHRASE_RX.match(v))


def count_scoring_hits(text, counts, counts_test, is_test):
    """Accumulate per-bucket regex-hit counts for one code file's text.

    For TEST_SPLIT_BUCKETS, hits in a test-only file (is_test) are tallied
    into `counts_test` instead of `counts` - they don't affect the score."""
    for key, patterns, _per, _cap, _lbl in SCORING_BUCKETS:
        if patterns is None:
            continue
        for i, rx in enumerate(patterns):
            hits = rx.findall(text)
            if not hits:
                continue
            if is_test and key in TEST_SPLIT_BUCKETS:
                counts_test[key] += len(hits)
                continue
            counts[key] += len(hits)
            if key == "hard_cred" and i == 0:
                counts["hard_cred_placeholder"] = (counts.get("hard_cred_placeholder", 0)
                                                     + sum(1 for v in hits if is_placeholder_value(v)))


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
            if key == "hard_cred" and metrics.get("hard_cred_placeholder", 0) > 0:
                ph = metrics["hard_cred_placeholder"]
                note += f" — {ph} of {n} look like placeholder value(s); verify"
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
            finding = {"sev": sev, "cat": cat, "why": why,
                       "loc": f"{rel}:{line_no}", "evidence": snippet}
            if cat == "Hardcoded secret" and is_placeholder_value(m.group(1)):
                finding["placeholder"] = True
            findings.append(finding)
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
    scanner_json_basename = ""  # link target (relative) for the scanner_results.json
    if args.scanners:
        try:
            scanner_json_basename = os.path.relpath(
                Path(args.scanners).resolve(), Path(args.output).resolve().parent).replace("\\", "/")
        except Exception:
            scanner_json_basename = os.path.basename(args.scanners)
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
    domain_src = {}  # domain -> set of files it was seen in (for trim attribution)
    caps = {key: {} for key, _title in INVENTORY_SECTIONS}  # reviewer inventory
    skill_md_text, fm = None, None
    scoring = {b[0]: 0 for b in SCORING_BUCKETS}  # dangerous/network/soft_cred/hard_cred/misplaced
    scoring["hard_cred_placeholder"] = 0  # subset of hard_cred whose value looks like a placeholder
    scoring_test = {k: 0 for k in TEST_SPLIT_BUCKETS}  # same buckets, but hits found only in tests/
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
                count_scoring_hits(text, scoring, scoring_test, is_test_path(rel))
            if p.name in ("SKILL.md", "README.md") or ext == ".md":
                text_blob.append(text[:4000])
            for m in URL_RE.finditer(text):
                d = m.group(1).lower()
                domains.setdefault(d, 0)
                domains[d] += 1
                domain_src.setdefault(d, set()).add(rel)
            for cat, token, line, extra in extract_inventory(rel, ext, text):
                slot = caps[cat].setdefault(token, {"locs": [], "extra": extra, "n": 0,
                                                    "code": False, "doc": False})
                slot["n"] += 1
                if not slot["extra"] and extra:
                    slot["extra"] = extra
                slot["code" if ext in EXEC_EXT else "doc"] = True
                loc = f"{rel.replace(chr(92), '/')}:{line}"
                if loc not in slot["locs"] and len(slot["locs"]) < 8:
                    slot["locs"].append(loc)
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
        src_files = sorted({rel for d in unknown_domains for rel in domain_src.get(d, ())})
        findings.append({"sev": SEV_WARN, "cat": "External domains",
                         "why": "Non-allowlisted domains referenced - verify each",
                         "loc": "-", "files": src_files,
                         "evidence": ", ".join(sorted(unknown_domains))[:300]})

    crit = [f for f in findings if f["sev"] == SEV_CRIT]
    warn = [f for f in findings if f["sev"] == SEV_WARN]
    info = [f for f in findings if f["sev"] == SEV_INFO]
    has_exec = any(i["kind"] == "executable" for i in inventory)
    has_bin = any(i["kind"] == "binary/archive" for i in inventory)

    def heuristic_tier(n_crit, n_warn, exec_present, bin_present):
        if bin_present or n_crit >= 2:
            return "REJECT / Tier 3", "binaries present or 2+ critical findings"
        if n_crit:
            return "Tier 3 (deep review)", "at least one critical finding to confirm or dismiss"
        if exec_present and n_warn:
            return "Tier 2 (standard review)", "executable content with warnings"
        if exec_present or n_warn:
            return "Tier 1-2 (depends on source & blast radius)", "executable content or warnings present"
        return "Tier 0-1 (depends on source & blast radius)", "instructions-only, no known patterns detected"

    tier, tier_why = heuristic_tier(len(crit), len(warn), has_exec, has_bin)

    # --- external scanner gate (run_scanners.py) folds into tier + report ----
    gate_verdict = gate["gate"] if gate else "NOT RUN"
    if gate and gate["gate"] == "BLOCK":
        tier = "REJECT / Tier 3"
        tier_why = "external scanner gate returned a blocking result (" + ", ".join(gate["blocking"]) + ")"

    # --- trim-to-install: which findings come from files the skill doesn't need ---
    # keys normalized to forward slashes so they match finding_file()'s output
    removable_index = {}  # rel(/) -> (reason_key, human_reason)
    for inv in inventory:
        rk, rw = classify_removable(inv["rel"])
        if rk:
            removable_index[inv["rel"].replace("\\", "/")] = (rk, rw)

    def finding_sources(f):
        if f.get("files") is not None:
            return [s.replace("\\", "/") for s in f["files"]]
        ff = finding_file(f.get("loc"))
        return [ff] if ff else []

    removable_stats = {SEV_CRIT: 0, SEV_WARN: 0, SEV_INFO: 0}
    removable_by_file = {}  # rel -> {"reason","why","CRITICAL","WARNING","INFO"}
    for f in findings:
        srcs = finding_sources(f)
        if srcs and all(s in removable_index for s in srcs):
            reasons = {removable_index[s][0] for s in srcs}
            key = next(iter(reasons)) if len(reasons) == 1 else "mixed"
            f["removable"] = key
            f["removable_why"] = REMOVABLE_REASON[key]
            removable_stats[f["sev"]] += 1
            primary = srcs[0]  # count each finding once, against its first source
            rk, rw = removable_index[primary]
            b = removable_by_file.setdefault(
                primary, {"reason": rk, "why": rw, SEV_CRIT: 0, SEV_WARN: 0, SEV_INFO: 0})
            b[f["sev"]] += 1
    removable_total = sum(removable_stats.values())
    trim_sorted = sorted(removable_by_file.items(),
                         key=lambda kv: (kv[1][SEV_CRIT], kv[1][SEV_WARN], kv[1][SEV_INFO]),
                         reverse=True)

    # projected heuristic counts/tier if the removable files were deleted
    proj_crit = len(crit) - removable_stats[SEV_CRIT]
    proj_warn = len(warn) - removable_stats[SEV_WARN]
    proj_info = len(info) - removable_stats[SEV_INFO]
    has_exec_after = any(i["kind"] == "executable" and i["rel"].replace("\\", "/") not in removable_index
                         for i in inventory)
    has_bin_after = any(i["kind"] == "binary/archive" and i["rel"].replace("\\", "/") not in removable_index
                        for i in inventory)
    proj_tier, _ = heuristic_tier(proj_crit, proj_warn, has_exec_after, has_bin_after)
    tier_changes = removable_total > 0 and proj_tier != tier and gate_verdict != "BLOCK"

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
        "hard_cred_placeholder": scoring["hard_cred_placeholder"],
    }
    metrics["misplaced"] = sum(1 for i in inventory if _is_script(i["rel"])
                               and _topdir(i["rel"]) not in EXPECTED_SCRIPT_DIRS)
    scoring["misplaced"] = metrics["misplaced"]
    metrics["test_only"] = dict(scoring_test)
    metrics["test_only_total"] = sum(scoring_test.values())

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
        if metrics["test_only_total"]:
            risk_bits += (f", plus {metrics['test_only_total']} hit(s) found only in tests/ "
                          "(not scored)")
        trim_bits = ""
        if removable_total:
            trim_bits = (
                f" Of the heuristic findings, **{removable_total}** "
                f"({removable_stats[SEV_CRIT]} critical / {removable_stats[SEV_WARN]} warning / "
                f"{removable_stats[SEV_INFO]} info) come from files the installed skill does not need "
                f"(tests, docs, backups, examples) — deleting those before install would leave "
                f"{proj_crit} critical / {proj_warn} warning / {proj_info} info"
                + (f" and lower the heuristic tier to **{proj_tier}**" if tier_changes else "")
                + " (see Metrics & risk score; re-run the scanner gate on the trimmed copy).")
        report_summary = (
            f"`{name}` is a **{category}** skill — {what_it_does[:200]}. The external scanner gate returned "
            f"**{gate_verdict}** and static heuristics produced {sev_bits}; the suggested review tier is "
            f"**{tier}**. "
            f"The structural/risk scan found {risk_bits}, giving a heuristic risk score of **{score}/100** → "
            f"**{recommendation}**"
            + (f" (forced by {', '.join(forced)})" if forced else "")
            + f". Author is **{author or 'unknown'}** (trust: {author_trust})."
            + trim_bits
            + " This score is a mechanical aid, "
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
        if scanner_json_basename:
            out.append(f"\n📄 Full scanner output: [`{os.path.basename(args.scanners)}`]({scanner_json_basename}) "
                       "(raw `scanner_results.json`; per-finding detail is also expanded per scanner in §3).")
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

    def build_html_report(main_html_name="", scanners_html_name=""):
        """Render the same data as an HTML document using assets/report-template.html
        (skill-dispatcher 'warm paper' visual language). Reuses every computed value
        so the HTML and markdown reports never drift. Returns (report_html,
        scanner_results_html) — the second is a styled rendering of scanner_results.json
        (empty string when the gate was not run)."""
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
                flag = (' <span class="badge flag" title="Looks like a placeholder value (e.g. \'change-this\', '
                        'a generic example, or a dictionary-word phrase) — still verify it isn\'t a real '
                        'credential.">⚑ placeholder?</span>') if f.get("placeholder") else ""
                rmv = (f' <span class="badge info" title="From a removable file ({esc(f.get("removable_why",""))}) '
                       '— deleting it before install clears this finding.">🗑 removable</span>') if f.get("removable") else ""
                out.append(
                    f'<div class="finding"><span class="badge {sev_badge(f["sev"])}">{esc(f["sev"])}</span> '
                    f'<span class="cat">{esc(f["cat"])}</span>{flag}{rmv} — {esc(f["why"])}'
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
            links = []
            if scanners_html_name:
                links.append(f'<a href="{esc(scanners_html_name)}">rendered scanner results</a>')
            if scanner_json_basename:
                links.append(f'<a href="{esc(scanner_json_basename)}">scanner_results.json</a>')
            if links:
                rows.append('<p class="note">📄 Full scanner output: ' + " · ".join(links) + "</p>")
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

        # --- §3 findings (grouped per scanner, then per severity) ---
        find_body = ('<h3>skill-vetting-reporter — static heuristics</h3>'
                     f'<h4>Critical ({len(crit)})</h4>{finding_rows(crit)}'
                     f'<h4>Warnings ({len(warn)})</h4>{finding_rows(warn)}'
                     f'<h4>Info ({len(info)})</h4>{finding_rows(info)}')
        sev_badge = {"critical": "block", "high": "block", "medium": "warn", "low": "info", "info": "info"}
        for r in (gate.get("results") if gate else []) or []:
            if r.get("status") not in ("ran", "ran (retried)"):
                continue
            meta = _scanner_meta(r)
            mbadge = (' <span class="badge block">BLOCK</span>' if r.get("block")
                      else ' <span class="badge pass">no block</span>')
            metatxt = f' <span class="note">{esc(" · ".join(meta))}</span>' if meta else ""
            find_body += f'<h3>{esc(r["name"])}{mbadge}{metatxt}</h3>'
            fnd = r.get("findings") or []
            sc = r.get("severity_counts", {}) or {}
            if not fnd:
                cnt = ", ".join(f"{k}:{sc[k]}" for k in ("critical", "high", "medium", "low") if sc.get(k))
                find_body += ('<p class="note">Per-finding detail not captured for this scanner'
                              + (f' (severity counts — {esc(cnt)})' if cnt else ' (no findings reported)')
                              + '. See the raw output in <code>scanner_results.json</code>.</p>')
                continue
            by = {}
            for f in fnd:
                by.setdefault(f.get("severity", "info"), []).append(f)
            for key, label in EXT_SEV_ORDER:
                grp = by.get(key) or []
                if not grp:
                    continue
                items = "".join(
                    f'<li><span class="badge {sev_badge.get(key, "info")}">{label}</span> {esc(f.get("title", "(finding)"))}'
                    + (f' — <code>{esc(f["location"])}</code>' if f.get("location") else "") + '</li>'
                    for f in grp)
                find_body += f'<h4>{label} ({len(grp)})</h4><ul>{items}</ul>'
            total = r.get("findings_total", len(fnd))
            if total > len(fnd):
                find_body += f'<p class="note">…and {total - len(fnd)} more (capped).</p>'

        # --- Reviewer inventory ---
        INV_TOKEN_CAP = 25

        def inv_locs_html(slot):
            shown = slot["locs"][:5]
            s = ", ".join(f'<code>{esc(l)}</code>' for l in shown)
            extra = slot["n"] - len(shown)
            return s + (f' <span class="note">+{extra} more</span>' if extra > 0 else "")

        def ctx_badge_html(slot):
            if slot.get("doc") and not slot.get("code"):
                return ' <span class="badge info">doc-only</span>'
            if slot.get("doc") and slot.get("code"):
                return ' <span class="badge info">code + docs</span>'
            return ""
        inv_parts = []
        if domains:
            dom_items = []
            for d, c in sorted(domains.items()):
                tag = ' <span class="badge warn">not allowlisted</span>' if d in unknown_domains else ''
                srcs = sorted(domain_src.get(d, []))
                ctx = "" if any(Path(s).suffix.lower() in EXEC_EXT for s in srcs) else ' <span class="badge info">doc-only</span>'
                src = ", ".join(f'<code>{esc(s.replace(chr(92), "/"))}</code>' for s in srcs[:5])
                dom_items.append(f'<li><code>{esc(d)}</code> ({c}×){tag}{ctx}{(" — " + src) if src else ""}</li>')
            inv_parts.append(f'<h3>Domains referenced</h3><ul>{"".join(dom_items)}</ul>')
        else:
            inv_parts.append('<h3>Domains referenced</h3><p class="empty">None.</p>')
        for key, title in INVENTORY_SECTIONS:
            slot = caps[key]
            if not slot:
                inv_parts.append(f'<h3>{esc(title)}</h3><p class="empty">None detected.</p>')
                continue
            if key == "library":
                third = sorted(t for t, s in slot.items() if s["extra"] == "third-party")
                builtin = sorted(t for t, s in slot.items() if s["extra"] in ("stdlib", "builtin"))
                body = ""
                if third:
                    body += "<p><strong>Third-party / external:</strong> " + ", ".join(f'<code>{esc(t)}</code>' for t in third) + "</p>"
                if builtin:
                    body += "<p><strong>Standard library / runtime builtins:</strong> " + ", ".join(f'<code>{esc(t)}</code>' for t in builtin) + "</p>"
                inv_parts.append(f'<h3>{esc(title)}</h3>{body}')
                continue
            toks = sorted(slot)
            items = "".join(f'<li><code>{esc(t)}</code> — {slot[t]["n"]}×{ctx_badge_html(slot[t])}: {inv_locs_html(slot[t])}</li>'
                            for t in toks[:INV_TOKEN_CAP])
            if len(toks) > INV_TOKEN_CAP:
                items += f'<li class="note">…and {len(toks) - INV_TOKEN_CAP} more</li>'
            inv_parts.append(f'<h3>{esc(title)}</h3><ul>{items}</ul>')
        inventory_body = (
            '<p class="note">Descriptive only — <strong>not scored</strong>. Aggregated across every file so a '
            'reviewer can see what the skill talks to, runs, downloads, and installs. Context tags: no tag = appears '
            'in executable code (it runs); <span class="badge info">doc-only</span> = appears only in prose and is '
            'not executed; <span class="badge info">code + docs</span> = both. Imports / execution sites / env / '
            'filesystem / dynamic-exec are read from code files only; tools, endpoints, listeners, installs, '
            'downloads and persistence targets from every file.</p>' + "".join(inv_parts))

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
        def build_decision_html():
            if not gate:
                return ""
            f = _decision_facts()
            h = [f'<h3>Scanner gate (§0) — why {esc(gate_verdict)}?</h3>']
            intro = f"{len(f['ran'])} scanner(s) ran"
            if f["ctx"]:
                intro += " (" + "; ".join(esc(c) for c in f["ctx"]) + ")"
            h.append(f'<p>{intro}:</p><ul>')
            for nm, desc, isblk in f["ran"]:
                blk = ' <span class="badge block">blocking</span>' if isblk else ''
                h.append(f'<li><strong>{esc(nm)}</strong>: {esc(desc)}.{blk}</li>')
            h.append('</ul>')
            if gate_verdict == "BLOCK":
                who = esc(", ".join(f["blocking"]) or "a scanner")
                h.append('<p class="note">The gate rule is simple: <strong>any high or critical finding from any '
                         f'scanner = BLOCK</strong>, regardless of the others. <strong>{who}</strong> alone is enough '
                         'to block. The individual findings are listed per scanner in §3.</p>')
            elif gate_verdict == "PASS":
                h.append('<p class="note">No scanner returned a blocking result, so the gate passes — but a clean '
                         'scan is <strong>not</strong> proof of safety; work §3–§5.</p>')
            else:
                h.append(f'<p class="note">The gate is <strong>{esc(gate_verdict)}</strong> — Tier 1+ approval is not '
                         'allowed until at least one scanner runs, or a reviewer records an explicit exception.</p>')
            h.append(f'<h3>Suggested tier (§6) — why {esc(tier)}?</h3>')
            h.append('<p>The tier is set by a two-factor rule: the gate verdict first, then the heuristic score.</p><ul>')
            if gate_verdict == "BLOCK":
                h.append(f'<li><strong>Gate overrides everything</strong>: a BLOCK forces <strong>REJECT / Tier 3</strong> '
                         f'regardless of the heuristics ({esc(tier_why)}).</li>')
            elif gate_verdict in ("INCOMPLETE", "NOT RUN"):
                h.append(f'<li><strong>Gate {esc(gate_verdict)}</strong>: blocks Tier 1+ approval until a scanner runs.</li>')
            else:
                h.append('<li><strong>Gate PASS</strong>: no blocking result, so the tier follows the heuristics, '
                         'source, and blast radius.</li>')
            if score_breakdown:
                inner = "; ".join(f"{esc(lbl)} {n} hit(s) → {esc(str(pen))}" for lbl, n, pen, _n in score_breakdown)
                forced_txt = f" (forced by {esc(', '.join(forced))})" if forced else ""
                h.append(f'<li><strong>Heuristic score {score}/100 → {esc(recommendation)}</strong>{forced_txt}: {inner}.</li>')
            else:
                h.append(f'<li><strong>Heuristic score {score}/100 → {esc(recommendation)}</strong>: no penalties — clean.</li>')
            if "dangerous" in forced:
                h.append('<li>The <strong>dangerous-call cap</strong> was reached, which forces a Decline independently '
                         'of the numeric score.</li>')
            if not writes_files and f["n_write"]:
                toks = ", ".join(f"<code>{esc(t)}</code>" for t in f["write_tokens"][:6])
                h.append('<li><strong>Description-alignment note</strong>: the frontmatter does not declare '
                         f'<code>dispatcher-writes-files: true</code>, but the scan found {f["n_write"]} file-write '
                         f'site(s) ({toks}) — worth confirming in §7.</li>')
            h.append('</ul>')
            return "".join(h)

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
            '</dl><p class="note"><strong>Other useful things to know</strong></p>' + notes_html
            + build_decision_html())

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
            ("Hard credential hits", metrics["hard_cred"]), ("Test-only hits (not scored)", metrics["test_only_total"]),
            ("Writes files (declared)", "Yes" if writes_files else "No")])
        bd_html = ("".join(f'<li>{esc(lbl)}: {n} hit(s) → {pen}{esc(note)}</li>' for lbl, n, pen, note in score_breakdown)
                   or "<li>No penalties.</li>")
        test_only_html = ("".join(f'<li>{esc(BUCKET_LABELS[k])}: {n} hit(s)</li>'
                                   for k, n in metrics["test_only"].items() if n)
                          or "<li>None.</li>")
        if removable_total:
            trim_rows = "".join(
                f'<tr><td><code>{esc(rel)}</code></td><td>{esc(b["why"])}</td>'
                f'<td>{b[SEV_CRIT]}</td><td>{b[SEV_WARN]}</td><td>{b[SEV_INFO]}</td></tr>'
                for rel, b in trim_sorted)
            delete_list = " ".join(f'<code>{esc(rel)}</code>' for rel, _ in trim_sorted)
            tier_line = (f'<p class="note">If trimmed, the heuristic tier would drop from '
                         f'<strong>{esc(tier)}</strong> to <strong>{esc(proj_tier)}</strong> — the scanner gate (§0) '
                         f'still reflects the full folder, so re-run it on the trimmed copy.</p>' if tier_changes else "")
            trim_html = (
                '<h3>Trim-to-install — findings from removable files</h3>'
                f'<p><span class="badge warn">{removable_total} finding(s) removable</span> '
                f'{removable_stats[SEV_CRIT]} critical / {removable_stats[SEV_WARN]} warning / '
                f'{removable_stats[SEV_INFO]} info come from files the installed skill does <strong>not</strong> need. '
                f'Deleting them before install would leave <strong>{proj_crit} critical / {proj_warn} warning / '
                f'{proj_info} info</strong>.</p>'
                + tier_line +
                '<table><thead><tr><th>File</th><th>Why removable</th><th>Crit</th><th>Warn</th><th>Info</th></tr></thead>'
                f'<tbody>{trim_rows}</tbody></table>'
                f'<p class="note"><strong>Delete before install to clear those findings:</strong> {delete_list}</p>'
                '<p class="note">A file is "removable" only if the installed skill never loads it at runtime: tests, '
                'human docs (README/CHANGELOG/CONTRIBUTING), backups (*.bak/*.orig), examples/fixtures, CI config, and '
                'lint/build config. SKILL.md, scripts/, references/, assets/ and LICENSE are always kept. '
                'Hard-credential hits are never treated as removable.</p>')
        else:
            trim_html = ('<h3>Trim-to-install — findings from removable files</h3>'
                         '<p class="empty">No heuristic findings come from removable files — every flag is in a file '
                         'the skill needs at runtime.</p>')
        metrics_body = (
            f'<p><span class="badge {rec_badge}">{score}/100 → {esc(recommendation)}</span>{forced_html}</p>'
            f'<table><thead><tr><th>Metric</th><th>Value</th></tr></thead><tbody>{mrows}</tbody></table>'
            f'<p class="note"><strong>Score breakdown (base 100):</strong></p><ul>{bd_html}</ul>'
            '<p class="note">Penalties: misplaced −5 (cap 4), dangerous −8 (cap 8 → forces Decline), network −2 '
            '(cap 12), soft-cred −5 (cap 4), hard-cred −40 (any hit forces Decline). Counted in code files only, '
            'so behaviour merely documented in markdown does not inflate the score. Complements — never replaces — '
            'the gate (§0) and tier (§6).</p>'
            f'<p class="note"><strong>Found only in test files (not scored):</strong></p><ul>{test_only_html}</ul>'
            '<p class="note">Dangerous/network/soft-credential patterns found only in test-path code '
            '(tests/, __tests__/, *.test.js/*.spec.ts, test_*.py/*_test.py/conftest.py) are listed here instead of '
            'counted above — deleting the tests would not reduce what the skill itself can do. Hard-credential hits '
            'are never split out this way. Still worth a quick look at what the test code actually executes.</p>'
            + trim_html)

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
            ("⚑ placeholder?", "The hardcoded-secret value looks like a placeholder (e.g. \"change-this\", "
                                "\"your-api-key-here\", a sample/dummy value, or a hyphenated word-phrase). "
                                "Still a finding — confirm it isn't a real credential before dismissing."),
            ("🗑 removable", "The finding comes from a file the installed skill does not need at runtime "
                             "(test, doc, backup, example, CI, or dev-config). Deleting that file before "
                             "install clears the finding without reducing the skill — see Metrics & risk score."),
        ])
        inventory_legend = legend_dl([
            ("__grp__", "Context tags (per entry)"),
            ("doc-only", "Appears only in prose/instructions (a .md/doc file) — it is NOT executed."),
            ("code + docs", "Appears in both executable code and documentation."),
            ("(no tag)", "Appears in executable code — it runs."),
            ("__grp__", "What each list aggregates (descriptive, not scored)"),
            ("Domains referenced", "Every host in a URL anywhere in the skill, with count, context and where; "
                                   "'not allowlisted' = not on the domain allowlist."),
            ("Process & shell execution sites", "Code that spawns a process/shell: subprocess, child_process, "
                                                "os.system/popen, execSync/spawnSync, Invoke-Expression (code files only)."),
            ("External CLI tools", "Named command-line tools referenced anywhere: git, npm, curl, docker, gh, pip, …"),
            ("Libraries / imports", "Modules the code imports, split into third-party vs standard-library / runtime builtins."),
            ("Outbound URLs / endpoints", "Full http(s) URLs the skill references whose host is NOT on the allowlist "
                                          "(allowlisted hosts are summarised under Domains)."),
            ("Network listeners / servers", "Server/port bindings: socket.bind, .listen(, createServer, app.run, "
                                            "uvicorn.run, Dockerfile EXPOSE, …"),
            ("Downloads", "Mechanisms that fetch remote content (curl/wget/requests.get/git clone/…) and direct archive URLs."),
            ("Installs", "Package/tool install commands (pip/npm/apt/brew/cargo/…) — including ones documented in a README."),
            ("Environment variables / secrets read", "Env vars the code reads (os.environ/getenv, process.env, $env:) — possible secrets."),
            ("Agent-config / persistence targets touched", "References to things that outlive the skill: CLAUDE.md/AGENTS.md, "
                                                           "settings.json, shell profiles, crontab, systemd, ~/.ssh, ~/.aws, .gitconfig."),
            ("Files written / created", "Filesystem writes (open(…, 'w'), write_text, fs.writeFile, Out-File, …)."),
            ("Files or directories deleted", "Filesystem deletions (os.remove, shutil.rmtree, Remove-Item, rm -rf, …)."),
            ("Dynamic code execution", "eval/exec/Function/compile and pickle/marshal deserialization sites."),
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
            ("Hard credential hits", "Literal secrets (keys/tokens/JWT/PEM) (-40 each, any -> Decline). "
                                      "Hits that look like placeholder values are noted but still counted "
                                      "and still force Decline — verify before treating as a false positive."),
            ("Test-only hits", "Dangerous/network/soft-credential patterns found ONLY in test-path code "
                                "(tests/, __tests__/, *.test.js/*.spec.ts, test_*.py/*_test.py/conftest.py). "
                                "Not counted above — deleting the tests would not reduce the skill's own "
                                "capabilities. Hard-credential hits are never split out this way."),
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
            section("", "Reviewer inventory — what the skill reaches, runs, and pulls in", inventory_body, inventory_legend),
            section("4", "OWASP Top 10 for Agentic Applications — coverage map", owasp_body, owasp_legend),
            section("", "Metrics & risk score", metrics_body, metrics_legend),
            section("5", "Red-flag checklist", checklist),
            section("6", "Suggested review tier", tier_body, tier_legend),
            section("7", "Reviewer judgement & sign-off", judge_body),
        ])
        gen = (f'<span>Generated {date.today().isoformat()}</span>'
               f'<span>Static heuristics + external scanner gate</span>'
               f'<span>Gate: {esc(gate_verdict)}</span>')
        report_html = (template.replace("{{TITLE}}", esc(name))
                       .replace("{{GENERATED_LINE}}", gen)
                       .replace("{{STAT_CARDS}}", stat_cards)
                       .replace("{{SECTIONS}}", sections))

        # --- companion page: scanner_results.json rendered in the same style ---
        def build_scanner_results_html():
            if not gate:
                return ""
            ev_sev = {"critical": "block", "high": "block", "medium": "warn", "low": "info", "info": "info"}
            secs = []
            back = (f'<p class="note"><a href="{esc(main_html_name)}">← back to the vetting report</a>'
                    f'{(" · <a href=" + chr(34) + esc(scanner_json_basename) + chr(34) + ">raw scanner_results.json</a>") if scanner_json_basename else ""}</p>')
            ov = (f'<p>Gate verdict: <strong>{esc(gate["gate"])}</strong> · '
                  f'{gate.get("scanners_ran", 0)}/{gate.get("scanners_total", 0)} scanner(s) ran · '
                  f'generated {esc(str(gate.get("generated_utc", "")))}.</p>' + back)
            secs.append(section("", "Scanner results — overview", ov))
            for r in gate["results"]:
                kv = ['<dl class="kv">', f'<dt>Status</dt><dd>{esc(str(r.get("status", "")))}</dd>']
                if r.get("command"):
                    kv.append(f'<dt>Command</dt><dd><code>{esc(str(r["command"]))}</code></dd>')
                sc = r.get("severity_counts", {}) or {}
                cnt = ", ".join(f"{k}:{sc[k]}" for k in ("critical", "high", "medium", "low") if sc.get(k)) or "none"
                kv.append(f'<dt>Severity counts</dt><dd>{esc(cnt)}</dd>')
                if r.get("risk_score") is not None:
                    kv.append(f'<dt>Risk score</dt><dd>{esc(str(r["risk_score"]))}</dd>')
                if r.get("recommendation"):
                    kv.append(f'<dt>Recommendation</dt><dd>{esc(str(r["recommendation"]))}</dd>')
                block_badge = '<span class="badge block">yes</span>' if r.get("block") else "no"
                kv.append(f'<dt>Block?</dt><dd>{block_badge}</dd>')
                if r.get("install_hint") and r.get("status") == "missing":
                    kv.append(f'<dt>Install</dt><dd><code>{esc(str(r["install_hint"]))}</code></dd>')
                if r.get("skip_reason"):
                    kv.append(f'<dt>Skip reason</dt><dd>{esc(str(r["skip_reason"]))}</dd>')
                kv.append("</dl>")
                body = "".join(kv)
                fnd = r.get("findings") or []
                if fnd:
                    by = {}
                    for f in fnd:
                        by.setdefault(f.get("severity", "info"), []).append(f)
                    for key, label in EXT_SEV_ORDER:
                        grp = by.get(key) or []
                        if not grp:
                            continue
                        items = "".join(
                            f'<li><span class="badge {ev_sev.get(key, "info")}">{label}</span> {esc(f.get("title", "(finding)"))}'
                            + (f' — <code>{esc(f["location"])}</code>' if f.get("location") else "") + "</li>" for f in grp)
                        body += f'<h4>{label} ({len(grp)})</h4><ul>{items}</ul>'
                    total = r.get("findings_total", len(fnd))
                    if total > len(fnd):
                        body += f'<p class="note">…and {total - len(fnd)} more (capped).</p>'
                if r.get("raw_tail"):
                    body += ('<details><summary>Raw output (tail)</summary>'
                             f'<pre style="white-space:pre-wrap;overflow:auto;max-height:420px" class="ev">{esc(str(r["raw_tail"]))}</pre></details>')
                secs.append(section("", r["name"], body))
            gcls = {"BLOCK": "is-block", "PASS": "is-pass", "INCOMPLETE": "is-warn"}.get(gate["gate"], "")
            scards = "".join([
                stat("Gate", gate["gate"], f'{gate.get("scanners_ran",0)}/{gate.get("scanners_total",0)} ran', gcls),
                stat("Blocking", sum(1 for r in gate["results"] if r.get("block")), "scanner(s)",
                     "is-block" if any(r.get("block") for r in gate["results"]) else ""),
            ])
            sgen = (f'<span>Generated {date.today().isoformat()}</span>'
                    f'<span>Rendered from scanner_results.json</span><span>Gate: {esc(gate["gate"])}</span>')
            return (template.replace("{{TITLE}}", esc(name + " — scanner results"))
                    .replace("{{GENERATED_LINE}}", sgen)
                    .replace("{{STAT_CARDS}}", scards)
                    .replace("{{SECTIONS}}", "".join(secs)))

        return report_html, build_scanner_results_html()

    EXT_SEV_ORDER = [("critical", "Critical"), ("high", "High"), ("medium", "Medium"),
                     ("low", "Low"), ("info", "Info")]

    def _scanner_meta(r):
        meta = []
        if r.get("risk_score") is not None:
            meta.append(f"score {r['risk_score']}")
        if r.get("recommendation"):
            meta.append(str(r["recommendation"]))
        if r.get("block"):
            meta.append("BLOCK")
        return meta

    def build_scanner_findings_md():
        """Per external scanner (that ran), its findings grouped by severity."""
        if not gate or not gate.get("results"):
            return ""
        blocks = []
        for r in gate["results"]:
            if r.get("status") not in ("ran", "ran (retried)"):
                continue
            meta = _scanner_meta(r)
            head = f"### {r['name']}" + (f" — {' · '.join(meta)}" if meta else "")
            fnd = r.get("findings") or []
            sc = r.get("severity_counts", {}) or {}
            if not fnd:
                cnt = ", ".join(f"{k}:{sc[k]}" for k in ("critical", "high", "medium", "low") if sc.get(k))
                note = (f"_Per-finding detail not captured for this scanner"
                        + (f" (severity counts — {cnt})" if cnt else " (no findings reported)")
                        + ". See §0 and the raw output in `scanner_results.json`._")
                blocks.append(head + "\n" + note)
                continue
            by = {}
            for f in fnd:
                by.setdefault(f.get("severity", "info"), []).append(f)
            sub = []
            for key, label in EXT_SEV_ORDER:
                grp = by.get(key) or []
                if not grp:
                    continue
                lines = [f"- {f.get('title', '(finding)')}"
                         + (f" — `{f['location']}`" if f.get("location") else "") for f in grp]
                sub.append(f"#### {label} ({len(grp)})\n" + "\n".join(lines))
            total = r.get("findings_total", len(fnd))
            if total > len(fnd):
                sub.append(f"_…and {total - len(fnd)} more (capped)._")
            blocks.append(head + "\n" + "\n".join(sub))
        return ("\n\n" + "\n\n".join(blocks) + "\n") if blocks else ""

    INV_TOKEN_CAP = 25  # max distinct tokens shown per inventory list

    def _ctx_tag_md(slot):
        if slot.get("doc") and not slot.get("code"):
            return " _(doc-only — not executed)_"
        if slot.get("doc") and slot.get("code"):
            return " _(code + docs)_"
        return ""

    def _inv_locs_md(slot):
        shown = slot["locs"][:5]
        s = ", ".join(f"`{l}`" for l in shown)
        extra = slot["n"] - len(shown)
        return s + (f" +{extra} more" if extra > 0 else "")

    def build_inventory_md():
        blocks = []
        # Domains (reuse the URL aggregation; also drives trim attribution)
        if domains:
            dl = []
            for d, c in sorted(domains.items()):
                tag = " — **NOT on allowlist**" if d in unknown_domains else ""
                srcs = sorted(domain_src.get(d, []))
                in_code = any(Path(s).suffix.lower() in EXEC_EXT for s in srcs)
                ctx = "" if in_code else " _(doc-only)_"
                src = ", ".join(f"`{s.replace(chr(92), '/')}`" for s in srcs[:5])
                dl.append(f"- `{d}` ({c}×){tag}{ctx}" + (f" — {src}" if src else ""))
            blocks.append("### Domains referenced\n" + "\n".join(dl))
        else:
            blocks.append("### Domains referenced\n_None._")
        for key, title in INVENTORY_SECTIONS:
            slot = caps[key]
            if not slot:
                blocks.append(f"### {title}\n_None detected._")
                continue
            if key == "library":
                third = sorted(t for t, s in slot.items() if s["extra"] == "third-party")
                builtin = sorted(t for t, s in slot.items() if s["extra"] in ("stdlib", "builtin"))
                sub = []
                if third:
                    sub.append("**Third-party / external:** " + ", ".join(f"`{t}`" for t in third))
                if builtin:
                    sub.append("**Standard library / runtime builtins:** " + ", ".join(f"`{t}`" for t in builtin))
                blocks.append(f"### {title}\n" + "\n\n".join(sub))
                continue
            toks = sorted(slot)
            lines = [f"- `{t}` — {slot[t]['n']}×{_ctx_tag_md(slot[t])}: {_inv_locs_md(slot[t])}"
                     for t in toks[:INV_TOKEN_CAP]]
            if len(toks) > INV_TOKEN_CAP:
                lines.append(f"- _…and {len(toks) - INV_TOKEN_CAP} more_")
            blocks.append(f"### {title}\n" + "\n".join(lines))
        return ("## Reviewer inventory (what the skill reaches, runs, and pulls in)\n\n"
                "_Descriptive only — **not scored**. Aggregated across every file so a reviewer can see at a "
                "glance what the skill talks to, runs, downloads, and installs. Each entry is tagged with its "
                "context: no tag = it appears in executable code (it runs); **doc-only** = it appears only in "
                "prose/instructions and is **not** executed; **code + docs** = both. Imports / execution sites / "
                "env / filesystem / dynamic-exec are read from code files only; tools, endpoints, listeners, "
                "installs, downloads and persistence targets are read from every file._\n\n"
                + "\n\n".join(blocks) + "\n")

    def _decision_facts():
        """Structured inputs for the 'why this verdict/tier' explanation."""
        ran, ctx, blocking = [], [], []
        for r in (gate.get("results") if gate else []) or []:
            st = r.get("status")
            if st in ("ran", "ran (retried)"):
                sc = r.get("severity_counts", {}) or {}
                cnt = ", ".join(f"{k}:{sc[k]}" for k in ("critical", "high", "medium", "low") if sc.get(k))
                sco, rec = r.get("risk_score"), r.get("recommendation")
                if not cnt and sco is None and not rec:
                    desc = "clean, no findings"
                else:
                    bits = ([cnt] if cnt else []) + ([f"score={sco}"] if sco is not None else []) + ([str(rec)] if rec else [])
                    desc = ", ".join(bits)
                ran.append((r["name"], desc, bool(r.get("block"))))
                if r.get("block"):
                    blocking.append(r["name"])
            elif st == "skipped":
                ctx.append(f"{r['name']} skipped ({r.get('skip_reason', 'no token/reason')})")
            elif st == "missing":
                ctx.append(f"{r['name']} not installed")
            elif st == "error":
                ctx.append(f"{r['name']} errored")
        return {"ran": ran, "ctx": ctx, "blocking": blocking,
                "n_write": sum(s["n"] for s in caps.get("fswrite", {}).values()),
                "write_tokens": sorted(caps.get("fswrite", {}))}

    def build_decision_md():
        if not gate:
            return ""
        f = _decision_facts()
        L = [f"### Scanner gate (§0) — why {gate_verdict}?"]
        intro = f"{len(f['ran'])} scanner(s) ran"
        if f["ctx"]:
            intro += " (" + "; ".join(f["ctx"]) + ")"
        L.append(intro + ":")
        for nm, desc, isblk in f["ran"]:
            L.append(f"- **{nm}**: {desc}." + ("  ← blocking" if isblk else ""))
        if gate_verdict == "BLOCK":
            who = ", ".join(f["blocking"]) or "a scanner"
            L.append(f"\nThe gate rule is simple: **any high or critical finding from any scanner = BLOCK**, "
                     f"regardless of what the other scanners say. **{who}** alone is enough to block. The "
                     "individual findings are listed per scanner in §3.")
        elif gate_verdict == "PASS":
            L.append("\nNo scanner returned a blocking result (no high/critical, score below the threshold), so the "
                     "gate passes — but a clean scan is **not** proof of safety; work §3–§5.")
        else:
            L.append(f"\nThe gate is **{gate_verdict}** — Tier 1+ approval is not allowed until at least one scanner "
                     "runs, or a reviewer records an explicit exception.")
        L.append(f"\n### Suggested tier (§6) — why {tier}?")
        L.append("The tier is set by a two-factor rule: the gate verdict first, then the heuristic score.")
        if gate_verdict == "BLOCK":
            L.append(f"- **Gate overrides everything**: a BLOCK forces **REJECT / Tier 3** regardless of the "
                     f"heuristics ({tier_why}).")
        elif gate_verdict in ("INCOMPLETE", "NOT RUN"):
            L.append(f"- **Gate {gate_verdict}**: blocks Tier 1+ approval until a scanner runs.")
        else:
            L.append("- **Gate PASS**: no blocking result, so the tier follows the heuristics, source, and blast radius.")
        if score_breakdown:
            inner = "; ".join(f"{lbl} {n} hit(s) → {pen}" for lbl, n, pen, _note in score_breakdown)
            L.append(f"- **Heuristic score {score}/100 → {recommendation}**"
                     + (f" (forced by {', '.join(forced)})" if forced else "") + f": {inner}.")
        else:
            L.append(f"- **Heuristic score {score}/100 → {recommendation}**: no penalties — the heuristic is clean.")
        if "dangerous" in forced:
            L.append("- The **dangerous-call cap** was reached, which forces a Decline independently of the numeric score.")
        if not writes_files and f["n_write"]:
            toks = ", ".join("`" + t + "`" for t in f["write_tokens"][:6])
            L.append(f"- **Description-alignment note**: the frontmatter does not declare "
                     f"`dispatcher-writes-files: true`, but the scan found {f['n_write']} file-write site(s) "
                     f"({toks}) — worth confirming in §7.")
        return "\n".join(L) + "\n"

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
{build_decision_md()}"""

    def build_metrics_md():
        forced_note = f" — **forced by {', '.join(forced)}**" if forced else ""
        bd = "".join(f"- {lbl}: {n} hit(s) → {pen}{note}\n" for lbl, n, pen, note in score_breakdown) or "- _No penalties._\n"
        yn = lambda b: "Yes" if b else "No"
        test_only = metrics["test_only"]
        test_only_lines = "".join(f"- {BUCKET_LABELS[k]}: {n} hit(s)\n" for k, n in test_only.items() if n) \
            or "- _None._\n"
        if removable_total:
            trim_table = "\n".join(
                f"| `{rel}` | {b['why']} | {b[SEV_CRIT]} | {b[SEV_WARN]} | {b[SEV_INFO]} |"
                for rel, b in trim_sorted)
            delete_list = "  ".join(f"`{rel}`" for rel, _ in trim_sorted)
            tier_line = (f"\n> If trimmed, the heuristic tier would drop from **{tier}** to **{proj_tier}** "
                         "(the scanner gate in §0 still reflects the full folder — re-run it on the trimmed copy)."
                         if tier_changes else "")
            trim_block = f"""
### Trim-to-install — findings from removable files

**{removable_total}** finding(s) ({removable_stats[SEV_CRIT]} critical / {removable_stats[SEV_WARN]} warning / {removable_stats[SEV_INFO]} info) come from files the installed skill does **not** need. Deleting them before install would leave **{proj_crit} critical / {proj_warn} warning / {proj_info} info**.{tier_line}

| File | Why removable | Crit | Warn | Info |
|---|---|--:|--:|--:|
{trim_table}

**Delete before install to clear those findings:** {delete_list}

> A file is "removable" only if the installed skill never loads it at runtime: tests, human docs
> (README/CHANGELOG/CONTRIBUTING), backups (`*.bak`/`*.orig`), examples/fixtures, CI config, and lint/build
> config. `SKILL.md`, `scripts/`, `references/`, `assets/` and `LICENSE` are always kept. Hard-credential hits
> are never treated as removable. The external scanner gate (§0) ran on the full folder — re-run it on the
> trimmed copy to confirm the gate verdict too.
"""
        else:
            trim_block = ("\n### Trim-to-install — findings from removable files\n\n"
                          "_No heuristic findings come from removable files — every flag is in a file the "
                          "skill needs at runtime._\n")
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
| Test-only hits (not scored) | {metrics['test_only_total']} |
| Writes files (declared) | {yn(writes_files)} |

Score breakdown (base 100):
{bd}
> Penalties: misplaced −5 (cap 4), dangerous −8 (cap 8 → forces Decline), network −2 (cap 12),
> soft-cred −5 (cap 4), hard-cred −40 (any hit forces Decline). Counted in code files only, so
> behaviour merely *documented* in markdown does not inflate the score. This score is a mechanical
> aid that complements — never replaces — the gate (§0) and tier (§6).

Found only in test files (not scored):
{test_only_lines}
> Dangerous/network/soft-credential patterns found *only* in test-path code (`tests/`,
> `__tests__/`, `*.test.js`/`*.spec.ts`, `test_*.py`/`*_test.py`/`conftest.py`) are listed here
> instead of counted above — deleting the tests would not reduce what the skill itself can do.
> Hard-credential hits are never split out this way: a real secret in a test fixture is still a
> real secret. Still worth a quick look at what the test code actually executes.
{trim_block}"""

    def fmt(fl):
        if not fl:
            return "_None detected._\n"
        out = ""
        for f in fl:
            out += f"- **[{f['cat']}]** {f['why']}\n  - `{f['loc']}`"
            if f["evidence"]:
                out += f" — `{f['evidence']}`"
            if f.get("placeholder"):
                out += "\n  - ⚑ _Looks like a placeholder value (e.g. \"change-this\", a generic example, or " \
                       "a dictionary-word phrase) — still verify it isn't a real credential._"
            if f.get("removable"):
                out += f"\n  - 🗑 _From a removable file ({f['removable_why']}) — deleting it before install " \
                       "clears this finding without reducing the skill._"
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

### skill-vetting-reporter — static heuristics
#### Critical ({len(crit)})
{fmt(crit)}
#### Warnings ({len(warn)})
{fmt(warn)}
#### Info ({len(info)})
{fmt(info)}
{build_scanner_findings_md()}
{build_inventory_md()}
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
        main_html_name = Path(html_path).name
        scanners_html_name = Path(html_path).stem + ".scanners.html" if gate else ""
        main_html, scanner_html = build_html_report(main_html_name, scanners_html_name)
        Path(html_path).write_text(main_html, encoding="utf-8")
        written["html"] = str(html_path)
        if scanner_html:
            scanners_path = Path(html_path).parent / scanners_html_name
            Path(scanners_path).write_text(scanner_html, encoding="utf-8")
            written["scanners_html"] = str(scanners_path)
    print(json.dumps({"files": len(inventory), "critical": len(crit), "warnings": len(warn),
                      "info": len(info), "suggested_tier": tier, "scanner_gate": gate_verdict,
                      "outputs": written}))


if __name__ == "__main__":
    main()
