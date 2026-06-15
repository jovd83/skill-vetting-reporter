#!/usr/bin/env python3
"""skill-vetting-reporter: external open-source scanner gate.

Runs the *mandatory automated scanning gate* that must precede human review for
any skill at Tier 1 or above. It orchestrates the free / open-source AgentSkill
scanners that are already installed on this machine, normalizes their results
into a single gate verdict, and writes a JSON summary that vet_skill.py folds
into the final report.

Supported scanners (all optional - detected, never auto-installed):
  - Cisco AI Defense skill-scanner   https://github.com/cisco-ai-defense/skill-scanner
  - NVIDIA SkillSpector              https://github.com/NVIDIA/SkillSpector
  - Snyk Agent Scan                  https://github.com/snyk/agent-scan
  - sentry/skill-scanner (community) https://github.com/getsentry/skills

Design rules (see SKILL.md "Hard rules"):
  - We invoke *external scanner binaries* against the target. We NEVER execute
    scripts that belong to the skill under review.
  - We never auto-install anything. Missing tools are reported with the exact
    install command so a human can add them. A gate with zero scanners run is
    INCOMPLETE, not PASS.
  - Snyk runs through `uvx`, which fetches & executes remote code on each run.
    That is only done when you explicitly pass --allow-uvx (opt-in), to respect
    a "don't silently fetch and run third-party code" posture.

Usage:
    python run_scanners.py <skill_dir_or_file> [-o scanner_results.json]
                           [--allow-uvx] [--enhanced] [--timeout 300]
                           [--skills-dir DIR ...]

Exit code: 0 if gate is PASS or INCOMPLETE, 2 if any scanner returned a
blocking result (BLOCK). This lets CI fail the build on a hard finding while
still surfacing "you have no scanner installed" as a soft (non-zero-coverage)
state for a human to resolve.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

# --- result vocabulary -------------------------------------------------------
RAN, MISSING, ERROR, SKIPPED = "ran", "missing", "error", "skipped"
GATE_PASS, GATE_BLOCK, GATE_INCOMPLETE = "PASS", "BLOCK", "INCOMPLETE"

# Words that, when a scanner emits them, mean "do not install / human stop".
BLOCK_MARKERS = re.compile(
    r"do\s*not\s*install|\bcritical\b|\bhigh\s*(risk|severity)\b|\bmalicious\b|\bblock(ed)?\b",
    re.IGNORECASE,
)

# A scanner failing on a control character (a stray TAB, or a C1 control like
# U+009D from a mangled em-dash) in the target's YAML frontmatter is
# deterministic - retrying the same command never helps; retrying against a copy
# with those characters normalized does. Cisco's strict loader emits e.g.
# "unacceptable character #x009d: control characters are not allowed".
RECOVERABLE_FRONTMATTER = re.compile(
    r"control characters? (are )?not allowed|unacceptable character|"
    r"special characters? which are not allowed|"
    r"found character that cannot start any token|"
    r"failed to (parse|load)[^\n]*frontmatter",
    re.IGNORECASE,
)

# Characters YAML forbids in plain content: C0 controls except TAB/LF/CR, DEL,
# and the C1 control block (U+0080-U+009F). TAB is handled separately (->spaces)
# because it is legal in content but breaks indentation.
ILLEGAL_YAML_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
# Genuinely transient failures - the same command may succeed on a second try.
TRANSIENT = re.compile(
    r"timed out|timeout|temporarily unavailable|connection (reset|refused|aborted|error)|"
    r"rate.?limit|too many requests|\b(429|500|502|503|504)\b|econnreset|read timed out|"
    r"network is unreachable|name resolution",
    re.IGNORECASE,
)


def classify_failure(text):
    """Bucket a scanner's failure so the caller can pick a retry strategy."""
    text = text or ""
    if RECOVERABLE_FRONTMATTER.search(text):
        return "frontmatter_tab"
    if TRANSIENT.search(text):
        return "transient"
    return None

# Default directories where installed AgentSkills (and thus the bundled
# sentry scan_skill.py) might live. Extra dirs can be added via --skills-dir.
DEFAULT_SKILLS_DIRS = [
    Path.home() / ".agents" / "skills",
    Path.home() / ".claude" / "skills",
]


def _which(*names):
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None


def _run(cmd, cwd, timeout):
    """Run an external scanner. Returns (exit_code, stdout, stderr, timed_out)."""
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or "", False
    except subprocess.TimeoutExpired as e:
        return None, (e.stdout or "") if isinstance(e.stdout, str) else "", "timeout", True
    except Exception as e:  # binary vanished, permissions, etc.
        return None, "", f"{type(e).__name__}: {e}", False


def _try_parse_json(text):
    """Tolerantly pull a JSON object out of scanner stdout (some tools print
    progress lines before the JSON)."""
    text = text.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        pass
    # find the first {...} or [...] block
    for opener, closer in (("{", "}"), ("[", "]")):
        start = text.find(opener)
        end = text.rfind(closer)
        if start != -1 and end > start:
            try:
                return json.loads(text[start:end + 1])
            except Exception:
                continue
    return None


def _deep_find(obj, keys):
    """Find the first value whose key (case-insensitive) is in `keys`,
    searching nested dicts/lists. Returns None if absent."""
    keyset = {k.lower() for k in keys}
    stack = [obj]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            for k, v in cur.items():
                if isinstance(k, str) and k.lower() in keyset and not isinstance(v, (dict, list)):
                    return v
                stack.append(v)
        elif isinstance(cur, list):
            stack.extend(cur)
    return None


def _find_list(obj, keys):
    """Find the first list value whose key (case-insensitive) is in `keys`,
    searching nested dicts/lists. Returns None if absent."""
    keyset = {k.lower() for k in keys}
    stack = [obj]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            for k, v in cur.items():
                if isinstance(k, str) and k.lower() in keyset and isinstance(v, list):
                    return v
                stack.append(v)
        elif isinstance(cur, list):
            stack.extend(cur)
    return None


def _top_level_str(obj, keys):
    """Return a string value for one of `keys`, looking only at the top-level
    dict (case-insensitive). Used for aggregate fields like a top-level
    `severity` that must NOT be confused with per-finding severities buried in
    a findings array."""
    if isinstance(obj, dict):
        low = {k.lower(): v for k, v in obj.items() if isinstance(k, str)}
        for k in keys:
            v = low.get(k.lower())
            if isinstance(v, str):
                return v
    return None


def _sev_bucket(value):
    """Map a free-form severity/level string onto one of our four buckets, or
    None for informational/safe levels that should not be counted."""
    if not isinstance(value, str):
        return None
    v = value.strip().lower()
    if v in ("critical", "crit"):
        return "critical"
    if v in ("high",):
        return "high"
    if v in ("medium", "moderate", "med"):
        return "medium"
    if v in ("low", "minor"):
        return "low"
    return None  # info / informational / safe / none / unknown -> not counted


def normalize(tool_id, exit_code, stdout, stderr, parsed):
    """Best-effort extraction of (severity_counts, score, recommendation, block?)
    from heterogeneous scanner output. Tolerant by design: schemas differ and
    evolve, so we fall back to scanning raw text for block markers."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    score = None
    recommendation = None

    if parsed is not None:
        # 1) aggregate count fields, when a scanner provides them outright
        for sev in list(counts):
            v = _deep_find(parsed, [f"{sev}_count", f"num_{sev}", f"{sev}s", sev])
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                counts[sev] = int(v)
        # 2) otherwise tally per-finding severities from a findings/issues array.
        #    SkillSpector reports `issues[].severity` (and no aggregate counts),
        #    so without this the table always showed "none" even on a score-100
        #    DO_NOT_INSTALL result.
        if not any(counts.values()):
            items = _find_list(parsed, ["findings", "issues", "vulnerabilities",
                                        "detections", "alerts", "results"]) or []
            for it in items:
                if isinstance(it, dict):
                    bucket = _sev_bucket(it.get("severity") or it.get("level")
                                         or it.get("risk") or it.get("max_severity"))
                    if bucket:
                        counts[bucket] += 1
        v = _deep_find(parsed, ["risk_score", "score", "risk"])
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            score = float(v)
        # recommendation/verdict: prefer unambiguous verdict-style keys (these
        # are safe to find at any depth, e.g. SkillSpector's
        # risk_assessment.recommendation = "DO_NOT_INSTALL"). Only fall back to a
        # bare top-level `severity`; a deep search for `severity` would wrongly
        # return an arbitrary per-finding severity from the issues array.
        r = _deep_find(parsed, ["recommendation", "install_recommendation",
                                "verdict", "max_severity", "overall_severity"])
        if not isinstance(r, str):
            r = _top_level_str(parsed, ["severity"])
        if isinstance(r, str):
            recommendation = r

    raw = f"{stdout}\n{stderr}"
    # block decision: explicit counts, score band, recommendation text, or raw markers
    block = (
        counts["critical"] > 0
        or counts["high"] > 0
        or (score is not None and score >= 51)
        or (recommendation is not None and BLOCK_MARKERS.search(recommendation) is not None)
        or (parsed is None and BLOCK_MARKERS.search(raw) is not None)
    )
    return {
        "severity_counts": counts,
        "risk_score": score,
        "recommendation": recommendation,
        "block": bool(block),
        "exit_code": exit_code,
    }


def _execute(cmd, cwd, timeout):
    """Run one scanner command, handling the {JSON_OUT} temp-file convention, and
    return a flat result dict. Isolated from the gate loop so retries can call it
    again with a modified command."""
    cmd = list(cmd)
    json_out_path = None
    if any("{JSON_OUT}" in part for part in cmd):
        fd, json_out_path = tempfile.mkstemp(suffix=".json", prefix="svr_")
        os.close(fd)
        cmd = [part.replace("{JSON_OUT}", json_out_path) for part in cmd]

    code, out, err, timed_out = _run(cmd, cwd, timeout)
    parsed = _try_parse_json(out)
    if json_out_path:
        try:
            file_text = Path(json_out_path).read_text(encoding="utf-8", errors="replace")
            file_parsed = _try_parse_json(file_text)
            if file_parsed is not None:
                parsed, out = file_parsed, file_text or out
        except Exception:
            pass
        finally:
            try:
                os.unlink(json_out_path)
            except OSError:
                pass
    return {"cmd": cmd, "code": code, "out": out, "err": err,
            "parsed": parsed, "timed_out": timed_out}


def _normalize_frontmatter(text):
    """Sanitize control characters *inside the YAML frontmatter block only*: TABs
    -> two spaces, and any other YAML-illegal control char (e.g. a C1 like U+009D
    from a mangled em-dash) -> a single space. Returns (new_text, changed). The
    body and everything after the frontmatter are left byte-identical - this is
    the minimum needed to let a strict YAML parser load the file, nothing more."""
    m = re.match(r"^(---\s*\n)(.*?\n)(---)", text, re.DOTALL)
    if not m:
        return text, False
    body = m.group(2)
    fixed = ILLEGAL_YAML_CTRL.sub(" ", body.replace("\t", "  "))
    if fixed == body:
        return text, False
    return text[:m.start()] + m.group(1) + fixed + m.group(3) + text[m.end():], True


def make_normalized_copy(target):
    """Build a temp copy of `target` whose SKILL.md frontmatter has control
    characters sanitized (see _normalize_frontmatter). Returns (path, changed).
    SECURITY: only frontmatter control characters are touched and the result is
    always labelled in the report as a normalized copy, so a scan against it is
    never mistaken for a scan of the original artifact. Returns (None/path,
    False) if there was nothing to normalize."""
    target = Path(target)
    tmp_root = Path(tempfile.mkdtemp(prefix="svr_norm_"))
    if target.is_file():
        dest = tmp_root / target.name
        text = target.read_text(encoding="utf-8", errors="replace")
        new_text, changed = (_normalize_frontmatter(text)
                             if target.name == "SKILL.md" else (text, False))
        dest.write_text(new_text, encoding="utf-8")
        return (str(dest), changed)
    dest = tmp_root / target.name
    shutil.copytree(target, dest)
    smd = dest / "SKILL.md"
    changed = False
    if smd.is_file():
        new_text, changed = _normalize_frontmatter(
            smd.read_text(encoding="utf-8", errors="replace"))
        if changed:
            smd.write_text(new_text, encoding="utf-8")
    return (str(dest), changed)


def _cleanup_norm(path):
    if path:
        shutil.rmtree(Path(path).parent, ignore_errors=True)


# --- scanner registry --------------------------------------------------------
# Each entry knows how to detect itself and how to build its command. We keep
# this declarative so adding the next scanner is a few lines, not a rewrite.

def scanner_definitions(target, allow_uvx, enhanced, skills_dirs):
    target = str(target)
    defs = []

    # 1) Cisco AI Defense skill-scanner -------------------------------------
    cisco = _which("skill-scanner")
    cisco_cmd = [cisco, "scan", target, "--format", "json"] if cisco else None
    if cisco_cmd and enhanced:
        cisco_cmd += ["--use-behavioral", "--use-llm", "--enable-meta"]
    defs.append({
        "id": "cisco-skill-scanner",
        "name": "Cisco AI Defense skill-scanner",
        "url": "https://github.com/cisco-ai-defense/skill-scanner",
        "found": bool(cisco),
        "cmd": cisco_cmd,
        "cwd": None,
        "install": "pip install cisco-ai-skill-scanner   # then: skill-scanner scan <path> --format json",
        "notes": "Signature + optional LLM semantic + behavioural dataflow. 'No findings != no risk.'",
    })

    # 2) NVIDIA SkillSpector ------------------------------------------------
    # Writes JSON via --output ({JSON_OUT} is substituted with a temp file by the
    # runner). Defaults to LLM providers that need API keys, so we pass --no-llm
    # for a pure-static run unless --enhanced is requested.
    spec = _which("skillspector")
    spec_cmd = None
    if spec:
        spec_cmd = [spec, "scan", target, "--format", "json", "--output", "{JSON_OUT}"]
        if not enhanced:
            spec_cmd.insert(3, "--no-llm")
    defs.append({
        "id": "skillspector",
        "name": "NVIDIA SkillSpector",
        "url": "https://github.com/NVIDIA/SkillSpector",
        "found": bool(spec),
        "cmd": spec_cmd,
        "cwd": None,
        "install": "git clone https://github.com/NVIDIA/SkillSpector && cd SkillSpector && uv venv && make install",
        "notes": "64 patterns / 16 categories incl. prompt injection, exfiltration, MCP tool poisoning. Risk score 0-100."
                 + ("" if enhanced else " (run with --no-llm; pass --enhanced for LLM analysis)"),
    })

    # 3) Snyk Agent Scan ----------------------------------------------------
    snyk_bin = _which("snyk-agent-scan")
    has_token = bool(os.environ.get("SNYK_TOKEN"))
    uvx = _which("uvx")
    snyk_cmd, snyk_found, snyk_note = None, False, ""
    if snyk_bin:
        snyk_cmd = [snyk_bin, target, "--json"]
        snyk_found = True
    elif allow_uvx and uvx:
        snyk_cmd = [uvx, "snyk-agent-scan@latest", target, "--json"]
        snyk_found = True
        snyk_note = " (via uvx; fetches & runs remote code)"
    # A missing token is a config gap, not a tool failure: skip cleanly instead
    # of running it just to collect an auth error.
    snyk_skip = "SNYK_TOKEN not set - export it to enable Snyk" if (snyk_found and not has_token) else None
    defs.append({
        "id": "snyk-agent-scan",
        "name": "Snyk Agent Scan",
        "url": "https://github.com/snyk/agent-scan",
        "found": snyk_found,
        "cmd": snyk_cmd,
        "cwd": None,
        "skip": snyk_skip,
        "install": "uvx snyk-agent-scan@latest <path> --json   # needs SNYK_TOKEN; pass --allow-uvx to fetch & run",
        "notes": "Auto-discovers skills/MCP across agents. Requires SNYK_TOKEN." + snyk_note,
    })

    # 4) sentry/skill-scanner (community, bundled scan_skill.py) -------------
    sentry_script = None
    for d in skills_dirs:
        cand = Path(d) / "skill-scanner" / "scripts" / "scan_skill.py"
        if cand.is_file():
            sentry_script = cand
            break
    sentry_runner = _which("uv") or _which("python", "python3")
    sentry_cmd = None
    if sentry_script and sentry_runner:
        runner_name = os.path.basename(sentry_runner).lower()
        if runner_name.startswith("uv") and not runner_name.startswith("uvx"):
            sentry_cmd = [sentry_runner, "run", str(sentry_script), target]
        else:
            sentry_cmd = [sentry_runner, str(sentry_script), target]
    defs.append({
        "id": "sentry-skill-scanner",
        "name": "sentry/skill-scanner (community)",
        "url": "https://github.com/getsentry/skills",
        "found": bool(sentry_cmd),
        "cmd": sentry_cmd,
        "cwd": str(sentry_script.parent.parent) if sentry_script else None,
        "install": "npx skills add https://github.com/getsentry/skills --skill skill-scanner",
        "notes": "Install-time scanner; bundled scan_skill.py runs static analysis. Looked under: "
                 + ", ".join(str(d) for d in skills_dirs),
    })

    return defs


def _classify_run(ex, timeout):
    """Turn an _execute result into (status, error_message). A non-zero exit with
    no parseable output and no block markers means the tool itself failed (e.g.
    missing SNYK_TOKEN) - ERROR, not a clean run. A non-zero exit *with*
    findings/markers is a real result."""
    if ex["timed_out"]:
        return ERROR, f"timed out after {timeout}s"
    if ex["code"] is None:
        return ERROR, ex["err"].strip()[:400]
    combined = f"{ex['out']}\n{ex['err']}"
    if ex["parsed"] is None and ex["code"] != 0 and not BLOCK_MARKERS.search(combined):
        return ERROR, (f"exited {ex['code']} with no parseable results - "
                       + (combined.strip()[:200] or "no output (check auth/config, e.g. SNYK_TOKEN)"))
    return RAN, None


def run_gate(target, allow_uvx, enhanced, timeout, skills_dirs,
             retries=1, normalize_retry=True):
    results = []
    for d in scanner_definitions(target, allow_uvx, enhanced, skills_dirs):
        entry = {
            "id": d["id"], "name": d["name"], "url": d["url"],
            "install_hint": d["install"], "notes": d["notes"],
        }
        if not d["found"] or not d["cmd"]:
            entry["status"] = MISSING
            results.append(entry)
            continue
        if d.get("skip"):
            entry["status"] = SKIPPED
            entry["skip_reason"] = d["skip"]
            results.append(entry)
            continue

        ex = _execute(d["cmd"], d["cwd"], timeout)
        entry["command"] = " ".join(ex["cmd"])
        status, errmsg = _classify_run(ex, timeout)

        # --- retry on failure, by failure class ---------------------------
        if status == ERROR:
            kind = classify_failure(f"{ex['out']}\n{ex['err']}")
            if kind == "frontmatter_tab" and normalize_retry:
                # deterministic parser failure: re-run once against a copy whose
                # frontmatter tabs are normalized to spaces (clearly labelled).
                norm_path, changed = make_normalized_copy(target)
                if changed and norm_path:
                    retry_cmd = [p.replace(str(target), norm_path) for p in d["cmd"]]
                    ex2 = _execute(retry_cmd, d["cwd"], timeout)
                    s2, e2 = _classify_run(ex2, timeout)
                    entry["retry"] = "frontmatter-normalized"
                    if s2 == RAN:
                        entry["retry_note"] = (
                            "original SKILL.md frontmatter contained YAML-illegal control character(s) "
                            "(e.g. a stray TAB or a C1 control like U+009D from a mangled em-dash) that "
                            "broke this scanner's strict parser; re-ran against a copy with frontmatter "
                            "control chars sanitized (body and other files unchanged).")
                        ex, status, errmsg = ex2, s2, e2
                    else:
                        entry["retry_note"] = "normalized-copy retry also failed: " + (e2 or "")
                else:
                    entry["retry"] = "frontmatter-normalized (no fixable control char found)"
                _cleanup_norm(norm_path)
            elif kind == "transient" and retries > 0:
                # same command may work on a second try; brief backoff
                for attempt in range(1, retries + 1):
                    time.sleep(min(2 * attempt, 5))
                    ex2 = _execute(d["cmd"], d["cwd"], timeout)
                    s2, e2 = _classify_run(ex2, timeout)
                    entry["retry"] = f"transient-x{attempt}"
                    ex, status, errmsg = ex2, s2, e2
                    if s2 != ERROR:
                        break

        if status == ERROR:
            entry["status"] = ERROR
            entry["error"] = errmsg
            results.append(entry)
            continue
        entry["status"] = RAN
        entry.update(normalize(d["id"], ex["code"], ex["out"], ex["err"], ex["parsed"]))
        # keep a trimmed raw tail for the reviewer, never the whole dump
        entry["raw_tail"] = (ex["out"].strip()[-600:] or ex["err"].strip()[-600:])
        results.append(entry)

    ran = [r for r in results if r["status"] == RAN]
    blocked = [r for r in ran if r.get("block")]
    if blocked:
        gate = GATE_BLOCK
    elif ran:
        gate = GATE_PASS
    else:
        gate = GATE_INCOMPLETE

    return {
        "schema": "skill-vetting-reporter/scanner-gate/v1",
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "target": str(target),
        "gate": gate,
        "scanners_ran": len(ran),
        "scanners_total": len(results),
        "blocking": [r["name"] for r in blocked],
        "results": results,
    }


def summarize(report):
    icon = {GATE_PASS: "PASS", GATE_BLOCK: "BLOCK", GATE_INCOMPLETE: "INCOMPLETE"}[report["gate"]]
    lines = [f"External scanner gate: {icon}  ({report['scanners_ran']}/{report['scanners_total']} scanners ran)"]
    for r in report["results"]:
        if r["status"] == RAN:
            sc = r.get("severity_counts", {})
            sev = ", ".join(f"{k}:{v}" for k, v in sc.items() if v)
            score = f" score={r['risk_score']}" if r.get("risk_score") is not None else ""
            flag = "  <-- BLOCK" if r.get("block") else ""
            retry = f"  (retried: {r['retry']})" if r.get("retry") else ""
            lines.append(f"  [ran]     {r['name']}: {sev or 'no findings'}{score}{flag}{retry}")
        elif r["status"] == MISSING:
            lines.append(f"  [missing] {r['name']}  -> {r['install_hint']}")
        elif r["status"] == SKIPPED:
            lines.append(f"  [skipped] {r['name']}: {r.get('skip_reason', '')}")
        else:
            lines.append(f"  [error]   {r['name']}: {r.get('error', '')[:120]}")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="Run the open-source AgentSkill scanner gate.")
    ap.add_argument("target", help="skill directory or file to scan")
    ap.add_argument("-o", "--output", default="scanner_results.json")
    ap.add_argument("--allow-uvx", action="store_true",
                    help="permit Snyk to run via uvx (fetches & runs remote code)")
    ap.add_argument("--enhanced", action="store_true",
                    help="enable heavier engines where supported (e.g. Cisco --use-llm; may need API keys)")
    ap.add_argument("--timeout", type=int, default=300, help="per-scanner timeout in seconds")
    ap.add_argument("--skills-dir", action="append", default=[],
                    help="extra directory to search for the sentry skill-scanner (repeatable)")
    ap.add_argument("--retries", type=int, default=1,
                    help="retries for transient failures (timeout/network); default 1")
    ap.add_argument("--no-normalize-retry", action="store_true",
                    help="disable the tabs->spaces frontmatter-normalized retry for strict YAML parsers")
    args = ap.parse_args()

    target = Path(args.target).resolve()
    if not target.exists():
        sys.exit(f"Not found: {target}")

    skills_dirs = [Path(d) for d in args.skills_dir] + DEFAULT_SKILLS_DIRS
    report = run_gate(target, args.allow_uvx, args.enhanced, args.timeout, skills_dirs,
                      retries=args.retries, normalize_retry=not args.no_normalize_retry)
    Path(args.output).write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(summarize(report))
    print(f"\nWrote {args.output}")
    if report["gate"] == GATE_INCOMPLETE:
        print("NOTE: no external scanner ran. Tier 1+ approval requires at least one. "
              "Install one of the tools above, or document the exception in the report.")
    sys.exit(2 if report["gate"] == GATE_BLOCK else 0)


if __name__ == "__main__":
    main()
