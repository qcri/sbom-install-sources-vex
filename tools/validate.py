"""Independent check of the reported results: re-parse the raw scanner output, recompute every row and the
verdict totals, and compare them with out/results.json and out/tables.md. Shares no code with run.py.

usage:  tar -xJf out/scans-2026-10-08.tar.xz      # or run `python3 -I run.py scan` first
        python3 -I tools/validate.py [out_dir]       # exit 0 = everything matches
"""
import json, re, sys
from pathlib import Path

OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent / "out"
TARGET = {"CVE-2020-14343", "GHSA-8q59-q68h-6hv4"}
VARIANTS = ["deb-unpatched", "deb-patched", "pypi", "git", "local", "local-backport", "pypi-fixed"]
PAIRS = [("syft", "grype"), ("syft", "trivy"), ("trivy", "grype"), ("trivy", "trivy")]


def grype(path):
    """Findings for the CVE in a Grype JSON report: (reported, suppressed) as sets of tuples."""
    doc = json.loads(path.read_text())
    is_target = lambda m: bool(({m["vulnerability"]["id"]} | {r["id"] for r in m.get("relatedVulnerabilities", [])}) & TARGET)
    reported = {(m["vulnerability"]["id"], m["artifact"]["purl"]) for m in doc["matches"] if is_target(m)}
    suppressed = {(m["vulnerability"]["id"], m["artifact"]["purl"],
                   ",".join(r.get("vex-status", r.get("reason", "?")) for r in m.get("appliedIgnoreRules", [])))
                  for m in doc.get("ignoredMatches", []) if is_target(m)}
    return reported, suppressed


def trivy(path):
    """Findings for the CVE in a Trivy JSON report: (reported, suppressed) as sets of tuples."""
    doc = json.loads(path.read_text())
    reported, suppressed = set(), set()
    for res in doc.get("Results", []):
        for f in res.get("Vulnerabilities") or []:
            if f["VulnerabilityID"] in TARGET:
                reported.add((f["VulnerabilityID"], f.get("PkgIdentifier", {}).get("PURL", f["PkgName"])))
        for m in res.get("ExperimentalModifiedFindings") or []:
            f = m.get("Finding", {})
            if f.get("VulnerabilityID") in TARGET:
                suppressed.add((f["VulnerabilityID"], f.get("PkgIdentifier", {}).get("PURL"), m.get("Status")))
    return reported, suppressed


def sarif_left(path):
    """Rule IDs for the CVE left in a SARIF file after vexctl filter, or None if the file is not SARIF."""
    try:
        doc = json.loads(path.read_text())
    except json.JSONDecodeError:
        return None
    return sorted(r["ruleId"] for run in doc.get("runs", []) for r in run.get("results", [])
                  if any(t in r["ruleId"] for t in TARGET))


def main():
    """Compare every recomputed row and the verdict totals with the committed outputs; return the exit code."""
    committed = json.loads((OUT / "results.json").read_text())
    tuples = lambda rows: {tuple(r) for r in rows}
    mismatches, wrong, pairs, rows = [], [0, 0, 0], 0, 0
    for v in VARIANTS:
        text = (OUT / v / "evidence.txt").read_text()
        vulnerable = json.loads(text.split("### ground truth (oracle)\n", 1)[1])["vulnerable"]
        docs = sorted(p.name[: -len(".openvex.json")] for p in (OUT / v).glob("*.openvex.json"))
        for sbom, scanner in PAIRS:
            parse = grype if scanner == "grype" else trivy
            scan = OUT / v / "scan"
            novex, _ = parse(scan / f"{scanner}.{sbom}.none.json")
            for doc in docs:
                rows += 1
                withvex, suppressed = parse(scan / f"{scanner}.{sbom}.{doc}.json")
                left = sarif_left(scan / f"{scanner}.{sbom}.vexctl-{doc}.sarif")
                c = committed[f"{v}|{sbom}|{scanner}|{doc}"]
                expected_left = None if c["vexctl_left"] is None else sorted(c["vexctl_left"])
                if (novex, withvex, suppressed, left) != (tuples(c["novex"]), tuples(c["vex"]), tuples(c["suppressed"]),
                                                          expected_left):
                    mismatches.append(f"{v}|{sbom}|{scanner}|{doc}")
                if doc == "vex":
                    pairs += 1
                    for i, reported in enumerate((bool(novex), bool(withvex), bool(left))):
                        wrong[i] += reported != vulnerable
    m = re.search(r"without VEX (\d+) of (\d+), with `--vex` (\d+) of \d+, with `vexctl filter` (\d+) of",
                  (OUT / "tables.md").read_text())
    reported_totals = [int(m[1]), int(m[3]), int(m[4])] if m else None
    print(f"rows checked: {rows}; rows differing from out/results.json: {len(mismatches)}")
    for k in mismatches:
        print("  DIFF", k)
    print(f"wrong verdicts over {pairs} pairs (without VEX, --vex, vexctl filter): {wrong}; "
          f"out/tables.md says {reported_totals}")
    return 0 if not mismatches and reported_totals == wrong and m and int(m[2]) == pairs else 1


if __name__ == "__main__":
    sys.exit(main())
