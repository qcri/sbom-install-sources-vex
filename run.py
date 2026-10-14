"""PyYAML 5.3.1 installed 7 ways -> SBOM (Syft, Trivy) -> supplier VEX (vexctl) -> scan (Grype, Trivy, vexctl filter).

Usage:  python3 -I run.py [stage ...]
        stages: fetch build evidence sbom vex scan report probe   (default: all, in that order)
Needs podman, curl, patch and network on first run. Everything is written to out/<variant>/.
The vulnerability DBs are downloaded on first use into .cache/ and then reused unchanged.
"""
import hashlib, json, os, re, shutil, subprocess, sys, tarfile
from pathlib import Path

LAB = Path(__file__).resolve().parent
OUT = LAB / "out"
CACHE = LAB / ".cache"
VEXCTL = LAB / "tools/vexctl"
TS = "2026-10-08T12:00:00Z"
CVE, GHSA = "CVE-2020-14343", "GHSA-8q59-q68h-6hv4"
TARGET = {CVE, GHSA}

SYFT = "docker.io/anchore/syft@sha256:507b76f097cd0f4a0f998a346afe61f5776329913d6ab3c0bd678b6635356120"  # 1.54.1
GRYPE = "docker.io/anchore/grype@sha256:e4a44ef45d285b829ce6efe2642980329661bd2d18eab5fc539138d4adaebbbe"  # v0.120.1
TRIVY = "docker.io/aquasec/trivy@sha256:af6acf9a6b85dfe389a1941505c0ce9efef52a4719635e1a962f022a3d855daa"  # 0.75.0
G_MOUNT = [f"{CACHE}/grype:/cache:Z"]
G_ENV = ["GRYPE_DB_CACHE_DIR=/cache", "GRYPE_DB_AUTO_UPDATE=false",
         "GRYPE_DB_VALIDATE_AGE=false"]   # keep using the frozen DB after Grype's 5-day age limit
T_MOUNT = [f"{CACHE}/trivy:/root/.cache/trivy:Z"]

# variant -> PURL the supplier knows it shipped (from its own build: dpkg version or wheel METADATA)
VARIANTS = {
    "deb-unpatched":  "pkg:deb/ubuntu/python3-yaml@5.3.1-1?arch=amd64&distro=ubuntu-20.04",
    "deb-patched":    "pkg:deb/ubuntu/python3-yaml@5.3.1-1ubuntu0.1?arch=amd64&distro=ubuntu-20.04",
    "pypi":           "pkg:pypi/pyyaml@5.3.1",
    "git":            "pkg:pypi/pyyaml@5.3.1",
    "local":          "pkg:pypi/pyyaml@5.3.1",
    "local-backport": "pkg:pypi/pyyaml@5.3.1%2Bacme1",
    "pypi-fixed":     "pkg:pypi/pyyaml@6.0.2",
}
SBOMS = ("syft", "trivy")

SDIST = ("https://files.pythonhosted.org/packages/source/P/PyYAML/PyYAML-5.3.1.tar.gz",
         "b8eac752c5e14d3eca0e6dd9199cd627518cb5ec06add0de9d32baeee6fe645d")
VEXCTL_BIN = ("https://github.com/openvex/vexctl/releases/download/v0.4.4/vexctl-linux-amd64",
              "d315e2778af88b999ad4bba30a08aa2677ed701638e16c341b6d57b43c1e064d")


def sh(*cmd, check=True, **kw):
    """Run a command and capture its output. With check=True, stop the pipeline on a non-zero exit."""
    r = subprocess.run(cmd, text=True, capture_output=True, **kw)
    if check and r.returncode:
        sys.exit(f"command failed (exit {r.returncode}): {' '.join(map(str, cmd))}\n{r.stderr[-3000:]}")
    return r


def pod(image, *args, mounts=(), env=()):
    """Run a tool container with out/ mounted at /out (plus extra mounts and env vars)."""
    vols = ["-v", f"{OUT}:/out:Z", *[a for m in mounts for a in ("-v", m)]]
    envs = [f"--env={e}" for e in env]
    return sh("podman", "run", "--rm", *vols, *envs, image, *args)


def dbs():
    """Download each scanner's vulnerability DB once. Later runs reuse it as is (no auto-update)."""
    for d in ("grype", "trivy"):
        (CACHE / d).mkdir(parents=True, exist_ok=True)
    if not list((CACHE / "grype").glob("*/vulnerability.db")):
        pod(GRYPE, "db", "update", mounts=G_MOUNT, env=["GRYPE_DB_CACHE_DIR=/cache"])
    if not (CACHE / "trivy/db/trivy.db").exists():
        pod(TRIVY, "image", "--download-db-only", mounts=T_MOUNT)


# ---------------------------------------------------------------- fetch / build / evidence / sbom
def download(url, sha, dest):
    """Download url to dest unless it is already there, and stop if its sha256 is not the expected one."""
    if not (dest.exists() and hashlib.sha256(dest.read_bytes()).hexdigest() == sha):
        dest.parent.mkdir(parents=True, exist_ok=True)
        sh("curl", "-sSfL", "-o", str(dest), url)
    got = hashlib.sha256(dest.read_bytes()).hexdigest()
    if got != sha:
        sys.exit(f"checksum mismatch for {dest}: {got}")


def fetch():
    """Source trees for the two local variants, and vexctl. All pinned by sha256."""
    src = LAB / "src"
    download(*SDIST, src / "dl/PyYAML-5.3.1.tar.gz")
    download(*VEXCTL_BIN, VEXCTL)
    VEXCTL.chmod(0o755)
    for d in ("pyyaml-5.3.1", "pyyaml-5.3.1-acme1", "PyYAML-5.3.1"):
        shutil.rmtree(src / d, ignore_errors=True)
    with tarfile.open(src / "dl/PyYAML-5.3.1.tar.gz") as t:
        t.extractall(src, filter="data")
    (src / "PyYAML-5.3.1").rename(src / "pyyaml-5.3.1")
    shutil.copytree(src / "pyyaml-5.3.1", src / "pyyaml-5.3.1-acme1")
    acme = src / "pyyaml-5.3.1-acme1"   # Ubuntu's patch (= upstream 7adc0db) + a local version label
    sh("patch", "-p1", "--no-backup-if-mismatch", "-i", str(src / "patches/CVE-2020-14343.patch"), cwd=acme)
    setup = acme / "setup.py"
    setup.write_text(setup.read_text().replace("VERSION = '5.3.1'", "VERSION = '5.3.1+acme1'"))


def build():
    """Build one image per variant, keep the build log, and save the image as a docker-archive tar."""
    for v in VARIANTS:
        r = sh("podman", "build", "-q", "-t", f"vexlab/{v}:1.0", "-f", f"variants/{v}/Containerfile", ".", cwd=LAB)
        (OUT / "build").mkdir(parents=True, exist_ok=True)
        (OUT / "build" / f"{v}.log").write_text(r.stderr + r.stdout)
        (OUT / v).mkdir(parents=True, exist_ok=True)
        (OUT / "images").mkdir(exist_ok=True)
        tar = OUT / f"images/{v}.tar"
        tar.unlink(missing_ok=True)
        sh("podman", "save", "-q", "--format", "docker-archive", "-o", str(tar), f"vexlab/{v}:1.0")


def evidence():
    """Run app/evidence.sh inside each image: package records, checksums and the oracle's verdict."""
    for v in VARIANTS:
        r = sh("podman", "run", "--rm", f"vexlab/{v}:1.0", "/app/evidence.sh")
        (OUT / v / "evidence.txt").write_text(r.stdout + r.stderr)


def oracle(v):
    """Ground truth for variant v: the oracle's JSON block from its evidence.txt."""
    text = (OUT / v / "evidence.txt").read_text()
    return json.loads(text.split("### ground truth (oracle)\n", 1)[1])


def sbom():
    """Generate a CycloneDX SBOM of each image with Syft and with Trivy."""
    dbs()
    for v in VARIANTS:
        pod(SYFT, "scan", f"docker-archive:/out/images/{v}.tar", "-q",
            "-o", f"cyclonedx-json=/out/{v}/sbom.syft.cdx.json")
        pod(TRIVY, "image", "-q", "--input", f"/out/images/{v}.tar", "--format", "cyclonedx",
            "--output", f"/out/{v}/sbom.trivy.cdx.json", mounts=T_MOUNT)


# ---------------------------------------------------------------- vex (the supplier's job)
def vex():
    """Example PSIRT writes one statement per variant. Status comes from the oracle, never from a scan."""
    for v, purl in VARIANTS.items():
        o = oracle(v)
        ev = f"PoC result: {o['poc result']}; constructor.py sha256 {o['constructor.py sha256'][:16]}..."
        docs = {}
        if o["vulnerable"]:
            docs["vex"] = ["--status", "affected", "--action-statement",
                           "Upgrade PyYAML to >= 5.4 (Ubuntu: python3-yaml 5.3.1-1ubuntu0.1), or replace "
                           "yaml.full_load with yaml.safe_load in handle_upload().", "--status-note", ev]
        else:
            docs["vex"] = ["--status", "fixed", "--status-note", ev]
        if v == "local-backport":   # the CISA question: is a backport 'fixed' or 'vulnerable_code_not_present'?
            docs["vex-vcnp"] = ["--status", "not_affected", "--justification", "vulnerable_code_not_present",
                                "--impact-statement", "Rebuild 5.3.1+acme1 carries the upstream CVE-2020-14343 "
                                "patch: FullLoader no longer registers python/object, python/object/new, "
                                "python/module. " + ev]
        for name, args in docs.items():
            f = OUT / v / f"{name}.openvex.json"
            sh(str(VEXCTL), "create", "--author", "Example PSIRT", "--author-role", "vendor",
               "--id", f"https://example.com/vex/{v}/{name}", "--product", purl,
               "--vuln", CVE, "--aliases", GHSA, *args, "--file", str(f),
               env={**os.environ, "SOURCE_DATE_EPOCH": TS})


def vex_files(v):
    """Names of the VEX documents written for variant v (e.g. ['vex', 'vex-vcnp'])."""
    return sorted(p.name.removesuffix(".openvex.json") for p in (OUT / v).glob("*.openvex.json"))


# ---------------------------------------------------------------- scan (the consumer's job)
def scan():
    """Scan every SBOM with Grype and Trivy: without VEX, with --vex, and with vexctl filter on the SARIF."""
    dbs()
    for v in VARIANTS:
        d = OUT / v / "scan"
        d.mkdir(exist_ok=True)
        for s in SBOMS:
            src = f"/out/{v}/sbom.{s}.cdx.json"
            for vx in ["none", *vex_files(v)]:
                vexarg = [] if vx == "none" else ["--vex", f"/out/{v}/{vx}.openvex.json"]
                base = f"/out/{v}/scan"
                pod(GRYPE,
                    f"sbom:{src}", "-q", "-o", f"json={base}/grype.{s}.{vx}.json",
                    "-o", f"sarif={base}/grype.{s}.{vx}.sarif", *vexarg, mounts=G_MOUNT, env=G_ENV)
                pod(TRIVY, "sbom", "-q", "--skip-db-update", "--scanners", "vuln", "-f", "json",
                    "-o", f"{base}/trivy.{s}.{vx}.json", *vexarg,
                    *(["--show-suppressed"] if vexarg else []), src, mounts=T_MOUNT)
                if vx == "none":
                    pod(TRIVY, "sbom", "-q", "--skip-db-update", "--scanners", "vuln", "-f", "sarif",
                        "-o", f"{base}/trivy.{s}.none.sarif", src, mounts=T_MOUNT)
            # post-filter style: plain scanner output, VEX applied afterwards by vexctl
            for sc in ("grype", "trivy"):
                for vx in vex_files(v):
                    r = sh(str(VEXCTL), "filter", str(d / f"{sc}.{s}.none.sarif"),
                           str(OUT / v / f"{vx}.openvex.json"), check=False)
                    (d / f"{sc}.{s}.vexctl-{vx}.sarif").write_text(r.stdout or r.stderr)


# ---------------------------------------------------------------- report
def grype_hits(p):
    """CVE-2020-14343 findings in a Grype JSON report: (reported, suppressed by VEX)."""
    j = json.loads(p.read_text())
    ids = lambda m: {m["vulnerability"]["id"], *[r["id"] for r in m.get("relatedVulnerabilities", [])]}
    hits = [(m["vulnerability"]["id"], m["artifact"]["purl"]) for m in j["matches"] if ids(m) & TARGET]
    sup = [(m["vulnerability"]["id"], m["artifact"]["purl"],
            ",".join(r.get("vex-status", r.get("reason", "?")) for r in m.get("appliedIgnoreRules", [])))
           for m in j.get("ignoredMatches", []) if ids(m) & TARGET]
    return hits, sup


def trivy_hits(p):
    """CVE-2020-14343 findings in a Trivy JSON report: (reported, suppressed by VEX)."""
    j = json.loads(p.read_text())
    hits, sup = [], []
    for r in j.get("Results", []):
        for x in r.get("Vulnerabilities", []):
            if x["VulnerabilityID"] in TARGET:
                hits.append((x["VulnerabilityID"], x.get("PkgIdentifier", {}).get("PURL", x["PkgName"])))
        for m in r.get("ExperimentalModifiedFindings", []):
            f = m.get("Finding", {})
            if f.get("VulnerabilityID") in TARGET:
                sup.append((f["VulnerabilityID"], f.get("PkgIdentifier", {}).get("PURL"), m.get("Status")))
    return hits, sup


def sarif_hits(p):
    """Rule IDs for CVE-2020-14343 left in a SARIF file, or None if vexctl wrote an error instead."""
    try:
        j = json.loads(p.read_text())
    except json.JSONDecodeError:
        return None
    return [r["ruleId"] for run in j.get("runs", []) for r in run.get("results", [])
            if any(t in r["ruleId"] for t in TARGET)]


def fmt(hits):
    """Findings as a Markdown cell: `ID` on `PURL`, one per line."""
    return "<br>".join(sorted({f"`{i}` on `{p}`" for i, p, *_ in hits})) or "—"


def verdict(reported, vulnerable):
    """Compare a scan with the oracle: ✅, ❌ FP (reported, not vulnerable) or ❌ FN (vulnerable, not reported)."""
    return "✅" if reported == vulnerable else ("❌ FP" if reported else "❌ FN")


def identity_fields(c):
    """Where a component records its deb source package and its install origin, besides name@version."""
    q = dict(kv.split("=", 1) for kv in c["purl"].partition("?")[2].split("&") if "=" in kv)
    props = {p["name"]: p["value"] for p in c.get("properties", [])}
    src = [f"purl `upstream={q['upstream']}`"] if "upstream" in q else []
    src += [f"`{k}={props[k]}`" for k in ("syft:metadata:source", "aquasecurity:trivy:SrcName") if k in props]
    origin = ["purl `vcs_url`"] if "vcs_url" in q else []
    origin += [f"{r['type']} reference `{r['url']}`" + (f" ({r['comment']})" if r.get("comment") else "")
               for r in c.get("externalReferences", [])]
    return src, origin


def report():
    """Write out/tables.md (identity and verdict tables) and out/results.json from the scan outputs."""
    rows, purl_rows, res = [], [], {}
    wrong, pairs = {"without VEX": 0, "with `--vex`": 0, "with `vexctl filter`": 0}, 0
    for v, vpurl in VARIANTS.items():
        o = oracle(v)
        truth = "vulnerable" if o["vulnerable"] else "not vulnerable"
        for s in SBOMS:
            b = json.loads((OUT / v / f"sbom.{s}.cdx.json").read_text())
            yc = sorted((c for c in b.get("components", [])
                         if c.get("purl") and re.search(r"/(python3-)?pyyaml@|/python3-yaml@", c["purl"], re.I)),
                        key=lambda c: c["purl"])
            purls = "<br>".join(f"`{c['purl']}`" for c in yc) or "—"
            src = "<br>".join(x for c in yc for x in identity_fields(c)[0]) or "—"
            origin = "<br>".join(x for c in yc for x in identity_fields(c)[1]) or "—"
            purl_rows.append(f"| {v} | {s} | {purls} | {src} | {origin} |")
            for sc, fn in (("grype", grype_hits), ("trivy", trivy_hits)):
                d = OUT / v / "scan"
                h0, _ = fn(d / f"{sc}.{s}.none.json")
                for vx in vex_files(v):
                    h1, sup = fn(d / f"{sc}.{s}.{vx}.json")
                    vc = sarif_hits(d / f"{sc}.{s}.vexctl-{vx}.sarif")
                    res[f"{v}|{s}|{sc}|{vx}"] = {"truth": truth, "novex": h0, "vex": h1, "suppressed": sup,
                                                 "vexctl_left": vc}
                    verdicts = [verdict(bool(h0), o["vulnerable"]), verdict(bool(h1), o["vulnerable"]),
                                "error" if vc is None else verdict(bool(vc), o["vulnerable"])]
                    if vx == "vex":   # count each SBOM->scanner pair once, with the variant's main statement
                        pairs += 1
                        for k, vd in zip(wrong, verdicts):
                            wrong[k] += vd != "✅"
                    vc_txt = "error" if vc is None else f"{len(vc)} left"
                    sup_txt = "<br>".join(sorted({f"{st}" for *_, st in sup})) or "—"
                    rows.append(f"| {v} | {truth} | {s}→{sc} | {vx} | {fmt(h0)} | {verdicts[0]} | {fmt(h1)} | "
                                f"{sup_txt} | {verdicts[1]} | {vc_txt} | {verdicts[2]} |")
    (OUT / "results.json").write_text(json.dumps(res, indent=1))
    summary = ", ".join(f"{k} {n} of {pairs}" for k, n in wrong.items())
    md = ["## PyYAML identity recorded by each SBOM generator", "",
          "| variant | SBOM generator | PyYAML PURL(s) | deb source package recorded in | "
          "install origin recorded outside name@version |", "|---|---|---|---|---|", *purl_rows, "",
          "## Verdicts for CVE-2020-14343 / GHSA-8q59-q68h-6hv4", "",
          "A verdict compares a scan with the oracle: ✅ agrees, ❌ FP reported but not vulnerable, "
          "❌ FN vulnerable but not reported. `vexctl filter` applies the same VEX document to the SARIF "
          "output of the scan without VEX.", "",
          "| variant | oracle | SBOM→scanner | VEX doc | findings without VEX | verdict | findings with `--vex` | "
          "suppressed as | verdict | `vexctl filter` (SARIF) | verdict |",
          "|---|---|---|---|---|---|---|---|---|---|---|", *rows, "",
          f"Wrong verdicts over the {pairs} SBOM→scanner pairs (each variant's `vex` document): {summary}."]
    (OUT / "tables.md").write_text("\n".join(md) + "\n")
    print("\n".join(md))


def probe():
    """Root-cause probes: change one field of an SBOM or of a VEX statement, or apply a statement to another
    image, and re-scan. Sections match RESULTS.md §4. 4.1 needs the images from `build`; 4.4 needs `scan`."""
    dbs()
    p, work, vm = OUT / "probe", OUT / "probe/work", OUT / "probe/vexmatch"
    for d in (p, work, vm):
        d.mkdir(parents=True, exist_ok=True)
    g = lambda src, *a: json.loads(pod(GRYPE, src, "-q", "-o", "json", *a, mounts=G_MOUNT, env=G_ENV).stdout)
    t = lambda sbom, *a: json.loads(pod(TRIVY, "sbom", "-q", "--skip-db-update", "--scanners", "vuln", "-f", "json",
                                        *a, f"/out/{sbom}", mounts=T_MOUNT).stdout)
    gh = lambda j: sorted({m["artifact"]["purl"].split("?")[0] for m in j["matches"]
                           if {m["vulnerability"]["id"], *[r["id"] for r in m.get("relatedVulnerabilities", [])]} & TARGET})
    th = lambda j: sorted({x["PkgIdentifier"]["PURL"].split("?")[0] for r in j.get("Results", [])
                           for x in r.get("Vulnerabilities", []) if x["VulnerabilityID"] in TARGET})
    grype_left = lambda sbom, *a: gh(g(f"sbom:/out/{sbom}", *a))
    trivy_left = lambda sbom, *a: th(t(sbom, *a))

    def patched(src, name, fn, keep=False):
        """Copy an SBOM and apply fn to its python3-yaml component. Kept copies go to probe/, the rest to probe/work/."""
        b = json.loads((OUT / src).read_text())
        for c in b["components"]:
            if c.get("name") == "python3-yaml":
                fn(c)
        f = (p if keep else work) / name
        f.write_text(json.dumps(b, indent=1) if keep else json.dumps(b))
        return str(f.relative_to(OUT))

    def statement(name, product, vuln=CVE, aliases=(GHSA,)):
        """Write a one-statement `fixed` VEX document to probe/vexmatch/ and return the --vex arguments."""
        alias = ["--aliases", ",".join(aliases)] if aliases else []
        sh(str(VEXCTL), "create", "--author", "Example PSIRT", "--id", f"https://example.com/vex/probe/{name}",
           "--product", product, "--vuln", vuln, *alias, "--status", "fixed",
           "--file", str(vm / f"{name}.openvex.json"), env={**os.environ, "SOURCE_DATE_EPOCH": TS})
        return "--vex", f"/out/probe/vexmatch/{name}.openvex.json"

    def vexctl_left(vex, keep):
        """vexctl-filter the pypi image's Trivy SARIF with a VEX document; keep the output, return what is left."""
        r = sh(str(VEXCTL), "filter", str(OUT / "pypi/scan/trivy.syft.none.sarif"), str(vex))
        (p / keep).write_text(r.stdout)
        return sorted(x["ruleId"] for run in json.loads(r.stdout)["runs"] for x in run["results"] if x["ruleId"] in TARGET)

    lines = ["# Each line lists the PURLs (qualifiers dropped) that still carry CVE-2020-14343 / GHSA-8q59-q68h-6hv4.",
             "# [] = nothing reported. VEX lines: [] = suppressed (or removed, for vexctl filter)."]
    out = lambda label, value: lines.append(f"{label:<70}: {value}")
    head = lambda title: lines.extend(["", f"## {title}"])

    head("4.1 One deb install, two components: does the PyPI duplicate survive outside CycloneDX?")
    for v in ("deb-unpatched", "deb-patched"):
        img, f = f"/out/images/{v}.tar", f"/out/probe/work/{v}"
        pod(SYFT, "scan", f"docker-archive:{img}", "-q", "-o", f"syft-json={f}.syft.json",
            "-o", f"spdx-json={f}.syft.spdx.json", "-o", f"cyclonedx-json={f}.syft.cdx.json")
        pod(TRIVY, "image", "-q", "--input", img, "--format", "spdx-json", "--output", f"{f}.trivy.spdx.json",
            mounts=T_MOUNT)
        sj = json.loads((work / f"{v}.syft.json").read_text())
        name = {a["id"]: a["name"] for a in sj["artifacts"]}
        out(f"{v}: Syft JSON relationship python3-yaml -> pyyaml",
            sorted({r["type"] for r in sj["artifactRelationships"]
                    if name.get(r["parent"]) == "python3-yaml" and name.get(r["child"]) == "pyyaml"}))
        sp = json.loads((work / f"{v}.syft.spdx.json").read_text())
        name = {x["SPDXID"]: x["name"] for x in sp["packages"]}
        out(f"{v}: Syft SPDX relationship python3-yaml -> pyyaml",
            sorted({f"{r['relationshipType']} ({r.get('comment', '').split(':')[0]})" for r in sp.get("relationships", [])
                    if name.get(r["spdxElementId"]) == "python3-yaml" and name.get(r["relatedSpdxElement"]) == "pyyaml"}))
        out(f"{v}: grype, image scanned directly", gh(g(f"docker-archive:{img}")))
        for ext, label in (("syft.json", "Syft JSON"), ("syft.spdx.json", "Syft SPDX"), ("syft.cdx.json", "Syft CycloneDX")):
            out(f"{v}: grype, {label} SBOM", grype_left(f"probe/work/{v}.{ext}"))
        for ext, label in (("syft.spdx.json", "Syft SPDX"), ("syft.cdx.json", "Syft CycloneDX")):
            out(f"{v}: trivy, {label} SBOM", trivy_left(f"probe/work/{v}.{ext}"))

    head("4.2 Deb source package: which field does each scanner read? (deb-unpatched, vulnerable)")
    tb, sb = "deb-unpatched/sbom.trivy.cdx.json", "deb-unpatched/sbom.syft.cdx.json"
    out("grype, Trivy SBOM as-is", grype_left(tb))
    out("grype, Trivy SBOM + purl qualifier upstream=pyyaml", grype_left(patched(
        tb, "deb-unpatched.trivy+upstream.cdx.json", lambda c: c.update(purl=c["purl"] + "&upstream=pyyaml"), keep=True)))
    out("grype, Trivy SBOM + Syft properties metadataType, metadata:source", grype_left(patched(
        tb, "trivy+syft-props.cdx.json", lambda c: c.setdefault("properties", []).extend(
            [{"name": "syft:package:metadataType", "value": "dpkg-db-entry"},
             {"name": "syft:metadata:source", "value": "pyyaml"}]))))
    out("grype, Trivy SPDX SBOM (source package only in sourceInfo text)", grype_left("probe/work/deb-unpatched.trivy.spdx.json"))
    no_q = lambda c: c.update(purl=c["purl"].replace("&upstream=pyyaml", ""))
    no_p = lambda c: c.update(properties=[x for x in c["properties"] if x["name"] != "syft:metadata:source"])
    out("grype, Syft SBOM as-is", grype_left(sb))
    out("grype, Syft SBOM minus purl qualifier upstream (property kept)", grype_left(patched(sb, "syft-q.cdx.json", no_q)))
    out("grype, Syft SBOM minus property syft:metadata:source (qualifier kept)", grype_left(patched(sb, "syft-p.cdx.json", no_p)))
    out("grype, Syft SBOM minus both", grype_left(patched(sb, "syft-qp.cdx.json", lambda c: (no_q(c), no_p(c)))))
    trivy_src = lambda *kv: lambda c: c["properties"].extend([{"name": f"aquasecurity:trivy:{k}", "value": v} for k, v in kv])
    out("trivy, Syft SBOM as-is", trivy_left(sb))
    out("trivy, Syft SBOM + property aquasecurity:trivy:SrcName=pyyaml", trivy_left(patched(
        sb, "syft+srcname.cdx.json", trivy_src(("SrcName", "pyyaml")))))
    out("trivy, Syft SBOM + SrcName=pyyaml, SrcVersion=5.3.1, SrcRelease=1", trivy_left(patched(
        sb, "deb-unpatched.syft+trivy-srcname.cdx.json",
        trivy_src(("SrcName", "pyyaml"), ("SrcVersion", "5.3.1"), ("SrcRelease", "1")), keep=True)))

    head("4.4 Applying a statement to another image: the patched deb's `fixed` statement on the vulnerable pypi image")
    wrong = "/out/deb-patched/vex.openvex.json"
    out("pypi Syft SBOM, grype --vex", grype_left("pypi/sbom.syft.cdx.json", "--vex", wrong))
    out("pypi Syft SBOM, trivy --vex", trivy_left("pypi/sbom.syft.cdx.json", "--vex", wrong))
    out("pypi Trivy SARIF, vexctl filter",
        vexctl_left(OUT / "deb-patched/vex.openvex.json", "pypi.trivy-sarif.filtered-with-deb-patched-vex.sarif"))
    other = statement("x-unrelated-npm", "pkg:npm/left-pad@1.0.0")
    out("unrelated pkg:npm/left-pad statement, pypi Syft SBOM, grype --vex", grype_left("pypi/sbom.syft.cdx.json", *other))
    out("unrelated pkg:npm/left-pad statement, pypi Syft SBOM, trivy --vex", trivy_left("pypi/sbom.syft.cdx.json", *other))
    out("unrelated pkg:npm/left-pad statement, pypi Trivy SARIF, vexctl filter",
        vexctl_left(vm / "x-unrelated-npm.openvex.json", "pypi.trivy-sarif.filtered-with-unrelated-vex.sarif"))

    head("4.5 How --vex matches: one field of the local-backport `fixed` statement changed")
    lb = VARIANTS["local-backport"]
    for name, product, vuln, aliases, targets in (
            ("a-no-alias", lb, CVE, (), ("local-backport", "pypi")),
            ("b-plain-5.3.1", "pkg:pypi/pyyaml@5.3.1", CVE, (GHSA,), ("local-backport", "pypi", "git")),
            ("c-no-version", "pkg:pypi/pyyaml", CVE, (GHSA,), ("local-backport", "pypi")),
            ("d-ghsa-only", lb, GHSA, (), ("local-backport",)),
            ("e-extra-qualifier", lb + "?foo=bar", CVE, (GHSA,), ("local-backport",))):
        arg = statement(name, product, vuln, aliases)
        for tgt in targets:
            sbom = f"{tgt}/sbom.syft.cdx.json"
            out(f"VEX {name} on {tgt} Syft SBOM", f"grype {grype_left(sbom, *arg)}, trivy {trivy_left(sbom, *arg)}")
    deb = "pkg:deb/ubuntu/python3-yaml@5.3.1-1?arch=amd64&distro=ubuntu-20.04"
    for name, product in (("f-deb-purl-as-trivy-writes-it", deb), ("g-deb-purl-as-syft-writes-it", deb + "&upstream=pyyaml")):
        arg = statement(name, product)
        out(f"VEX {name} on deb-unpatched", f"syft→grype {grype_left(sb, *arg)}, trivy→trivy {trivy_left(tb, *arg)}")
    (p / "probes.txt").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


STAGES = {"fetch": fetch, "build": build, "evidence": evidence, "sbom": sbom, "vex": vex, "scan": scan, "report": report,
          "probe": probe}

if __name__ == "__main__":
    for st in sys.argv[1:] or STAGES:
        print(f"== {st}", file=sys.stderr)
        STAGES[st]()
