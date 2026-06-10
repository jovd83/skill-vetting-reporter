#!/usr/bin/env python3
"""skill-vetting-reporter: batch roll-up.

Vet a whole directory of skills in one go. For each subdirectory that contains a
SKILL.md, it runs the external scanner gate (run_scanners.py) and the heuristic
report (vet_skill.py), then writes a single roll-up table so a reviewer can see
at a glance which skills need attention and in what order.

It does not change how an individual skill is judged - it just fans the existing
two-script pipeline across many targets and sorts the results by risk. Each skill
keeps its own full report and sign-off trail under the output directory.

Usage:
    python vet_batch.py <dir-of-skills> [-o vetting-batch]
                        [--allow-uvx] [--enhanced] [--timeout 300]
                        [--retries 1] [--no-normalize-retry] [--skills-dir DIR]

Exit code: 2 if any skill's gate is BLOCK, else 0.
"""
import argparse
import json
import subprocess
import sys
from datetime import date
from pathlib import Path

HERE = Path(__file__).resolve().parent
RUN_SCANNERS = HERE / "run_scanners.py"
VET_SKILL = HERE / "vet_skill.py"


def discover_skills(parent):
    """Immediate subdirectories that contain a SKILL.md. If none, but the parent
    itself is a skill, treat the parent as a single target."""
    parent = Path(parent)
    skills = sorted(p for p in parent.iterdir() if p.is_dir() and (p / "SKILL.md").is_file())
    if not skills and (parent / "SKILL.md").is_file():
        skills = [parent]
    return skills


def tier_rank(tier, gate):
    """Higher = more urgent, for sorting the roll-up."""
    if gate == "BLOCK" or "REJECT" in (tier or ""):
        return 100
    for n in ("3", "2", "1"):
        if n in (tier or ""):
            return int(n)
    return 0


def vet_one(skill_dir, out_dir, common_args, timeout):
    name = skill_dir.name
    sk_out = out_dir / name
    sk_out.mkdir(parents=True, exist_ok=True)
    scan_json = sk_out / "scan.json"
    report_md = sk_out / "report.md"

    gate_proc = subprocess.run(
        [sys.executable, str(RUN_SCANNERS), str(skill_dir), "-o", str(scan_json),
         "--timeout", str(timeout)] + common_args,
        capture_output=True, text=True)

    rep_proc = subprocess.run(
        [sys.executable, str(VET_SKILL), str(skill_dir), "-o", str(report_md),
         "--scanners", str(scan_json)],
        capture_output=True, text=True)

    # vet_skill.py prints a JSON summary on its last stdout line
    summary = {}
    for line in reversed((rep_proc.stdout or "").splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                summary = json.loads(line)
                break
            except json.JSONDecodeError:
                continue

    ran = total = None
    gate = summary.get("scanner_gate")
    try:
        gate_data = json.loads(scan_json.read_text(encoding="utf-8"))
        ran, total = gate_data.get("scanners_ran"), gate_data.get("scanners_total")
        gate = gate or gate_data.get("gate")
    except Exception:
        pass

    return {
        "name": name,
        "path": str(skill_dir),
        "gate": gate or "NOT RUN",
        "scanners": f"{ran}/{total}" if ran is not None else "-",
        "critical": summary.get("critical", "?"),
        "warnings": summary.get("warnings", "?"),
        "tier": summary.get("suggested_tier", "?"),
        "report": str(report_md),
        "gate_exit": gate_proc.returncode,
    }


def main():
    ap = argparse.ArgumentParser(description="Batch roll-up vetting for a directory of skills.")
    ap.add_argument("parent", help="directory containing skill subdirectories")
    ap.add_argument("-o", "--output-dir", default="vetting-batch")
    ap.add_argument("--allow-uvx", action="store_true")
    ap.add_argument("--enhanced", action="store_true")
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--retries", type=int, default=1)
    ap.add_argument("--no-normalize-retry", action="store_true")
    ap.add_argument("--skills-dir", action="append", default=[])
    args = ap.parse_args()

    parent = Path(args.parent).resolve()
    if not parent.is_dir():
        sys.exit(f"Not a directory: {parent}")
    skills = discover_skills(parent)
    if not skills:
        sys.exit(f"No skills (directories with a SKILL.md) found under {parent}")

    # arguments forwarded verbatim to run_scanners.py
    common = []
    if args.allow_uvx:
        common.append("--allow-uvx")
    if args.enhanced:
        common.append("--enhanced")
    if args.retries != 1:
        common += ["--retries", str(args.retries)]
    if args.no_normalize_retry:
        common.append("--no-normalize-retry")
    for d in args.skills_dir:
        common += ["--skills-dir", d]

    out_dir = Path(args.output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    rows = []
    for sk in skills:
        print(f"  vetting {sk.name} ...", flush=True)
        rows.append(vet_one(sk, out_dir, common, args.timeout))

    rows.sort(key=lambda r: (tier_rank(r["tier"], r["gate"]),
                             r["critical"] if isinstance(r["critical"], int) else 0),
              reverse=True)

    blocks = [r for r in rows if r["gate"] == "BLOCK"]
    md = [f"# Batch vetting roll-up — `{parent.name}`",
          "",
          f"> Generated by skill-vetting-reporter on {date.today().isoformat()}. "
          f"{len(rows)} skill(s) scanned. Each skill keeps its own full report "
          "(linked below); complete every report's reviewer sign-off before approval.",
          ""]
    if blocks:
        md.append(f"**⛔ {len(blocks)} skill(s) returned a BLOCK gate — review these first.**\n")
    md += ["| Skill | Gate | Scanners | Critical | Warnings | Suggested tier | Report |",
           "|---|---|---|---|---|---|---|"]
    for r in rows:
        rp = Path(r["report"])
        rel = rp.relative_to(out_dir).as_posix() if rp.is_relative_to(out_dir) else rp.name
        md.append(f"| `{r['name']}` | {r['gate']} | {r['scanners']} | {r['critical']} | "
                  f"{r['warnings']} | {r['tier']} | [report]({rel}) |")
    md.append("")
    (out_dir / "batch_summary.md").write_text("\n".join(md), encoding="utf-8")
    (out_dir / "batch_summary.json").write_text(
        json.dumps({"parent": str(parent), "generated": date.today().isoformat(),
                    "count": len(rows), "rows": rows}, indent=2), encoding="utf-8")

    print(f"\nRoll-up: {len(rows)} skill(s) — "
          f"{sum(1 for r in rows if r['gate']=='BLOCK')} BLOCK, "
          f"{sum(1 for r in rows if r['gate']=='INCOMPLETE')} INCOMPLETE.")
    print(f"Wrote {out_dir / 'batch_summary.md'}")
    sys.exit(2 if blocks else 0)


if __name__ == "__main__":
    main()
