"""PyYAML 5.3.1 installed 7 ways -> SBOM (Syft, Trivy) -> supplier VEX (vexctl) -> scan (Grype, Trivy, vexctl filter).

Usage:  python3 -I run.py [stage ...]
        stages: fetch build evidence sbom vex scan report probe   (default: all, in that order)
Needs podman, curl, patch and network on first run. Everything is written to out/<variant>/.
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
GRYPE = "docker.io/anchore/grype:v0.120.1"
TRIVY = "docker.io/aquasec/trivy:0.75.0"

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
    return subprocess.run(cmd, check=check, text=True, capture_output=True, **kw)


def pod(image, *args, mounts=(), env=()):
    vols = ["-v", f"{OUT}:/out:Z", *[a for m in mounts for a in ("-v", m)]]
    envs = [f"--env={e}" for e in env]
    return sh("podman", "run", "--rm", *vols, *envs, image, *args, check=False)


# ---------------------------------------------------------------- fetch / build / evidence / sbom
def download(url, sha, dest):
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
    for v in VARIANTS:
        sh("podman", "build", "-q", "-t", f"vexlab/{v}:1.0", "-f", f"variants/{v}/Containerfile", ".", cwd=LAB)
        (OUT / v).mkdir(parents=True, exist_ok=True)
        (OUT / "images").mkdir(exist_ok=True)
        tar = OUT / f"images/{v}.tar"
        tar.unlink(missing_ok=True)
        sh("podman", "save", "-q", "--format", "docker-archive", "-o", str(tar), f"vexlab/{v}:1.0")


def evidence():
    for v in VARIANTS:
        r = sh("podman", "run", "--rm", f"vexlab/{v}:1.0", "/app/evidence.sh")
        (OUT / v / "evidence.txt").write_text(r.stdout + r.stderr)


def oracle(v):
    text = (OUT / v / "evidence.txt").read_text()
    return json.loads(text.split("### ground truth (oracle)\n", 1)[1])


def sbom():
    for v in VARIANTS:
        pod(SYFT, "scan", f"docker-archive:/out/images/{v}.tar", "-q",
            "-o", f"cyclonedx-json=/out/{v}/sbom.syft.cdx.json")
        pod(TRIVY, "image", "-q", "--input", f"/out/images/{v}.tar", "--format", "cyclonedx",
            "--output", f"/out/{v}/sbom.trivy.cdx.json", mounts=[f"{CACHE}/trivy:/root/.cache/trivy:Z"])


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
    return sorted(p.name.removesuffix(".openvex.json") for p in (OUT / v).glob("*.openvex.json"))


# ---------------------------------------------------------------- scan (the consumer's job)
def scan():
    g_mount = [f"{CACHE}/grype:/cache:Z"]
    t_mount = [f"{CACHE}/trivy:/root/.cache/trivy:Z"]
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
                    "-o", f"sarif={base}/grype.{s}.{vx}.sarif", *vexarg, mounts=g_mount,
                    env=["GRYPE_DB_CACHE_DIR=/cache", "GRYPE_DB_AUTO_UPDATE=false"])
                pod(TRIVY, "sbom", "-q", "--skip-db-update", "--scanners", "vuln", "-f", "json",
                    "-o", f"{base}/trivy.{s}.{vx}.json", *vexarg,
                    *(["--show-suppressed"] if vexarg else []), src, mounts=t_mount)
                if vx == "none":
                    pod(TRIVY, "sbom", "-q", "--skip-db-update", "--scanners", "vuln", "-f", "sarif",
                        "-o", f"{base}/trivy.{s}.none.sarif", src, mounts=t_mount)
            # post-filter style: plain scanner output, VEX applied afterwards by vexctl
            for sc in ("grype", "trivy"):
                for vx in vex_files(v):
                    r = sh(str(VEXCTL), "filter", str(d / f"{sc}.{s}.none.sarif"),
                           str(OUT / v / f"{vx}.openvex.json"), check=False)
                    (d / f"{sc}.{s}.vexctl-{vx}.sarif").write_text(r.stdout or r.stderr)


# ---------------------------------------------------------------- report
def grype_hits(p):
    j = json.loads(p.read_text())
    ids = lambda m: {m["vulnerability"]["id"], *[r["id"] for r in m.get("relatedVulnerabilities", [])]}
    hits = [(m["vulnerability"]["id"], m["artifact"]["purl"]) for m in j["matches"] if ids(m) & TARGET]
    sup = [(m["vulnerability"]["id"], m["artifact"]["purl"],
            ",".join(r.get("vex-status", r.get("reason", "?")) for r in m.get("appliedIgnoreRules", [])))
           for m in j.get("ignoredMatches", []) if ids(m) & TARGET]
    return hits, sup


def trivy_hits(p):
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
    try:
        j = json.loads(p.read_text())
    except json.JSONDecodeError:
        return None
    return [r["ruleId"] for run in j.get("runs", []) for r in run.get("results", [])
            if any(t in r["ruleId"] for t in TARGET)]


def fmt(hits):
    return "<br>".join(sorted({f"`{i}` on `{p}`" for i, p, *_ in hits})) or "—"


def report():
    rows, purl_rows, res = [], [], {}
    for v, vpurl in VARIANTS.items():
        o = oracle(v)
        truth = "vulnerable" if o["vulnerable"] else "not vulnerable"
        for s in SBOMS:
            b = json.loads((OUT / v / f"sbom.{s}.cdx.json").read_text())
            yp = sorted({c.get("purl") for c in b.get("components", [])
                         if c.get("purl") and re.search(r"/(python3-)?pyyaml@|/python3-yaml@", c["purl"], re.I)})
            purl_rows.append(f"| {v} | {s} | {'<br>'.join(f'`{x}`' for x in yp) or '—'} |")
            for sc, fn in (("grype", grype_hits), ("trivy", trivy_hits)):
                d = OUT / v / "scan"
                h0, _ = fn(d / f"{sc}.{s}.none.json")
                for vx in vex_files(v):
                    h1, sup = fn(d / f"{sc}.{s}.{vx}.json")
                    vc = sarif_hits(d / f"{sc}.{s}.vexctl-{vx}.sarif")
                    final = "reported" if h1 else "not reported"
                    ok = (final == "reported") == o["vulnerable"]
                    res[f"{v}|{s}|{sc}|{vx}"] = {"truth": truth, "novex": h0, "vex": h1, "suppressed": sup,
                                                 "vexctl_left": vc}
                    vc_txt = "error" if vc is None else (f"{len(vc)} left" if vc else "0 left")
                    rows.append(f"| {v} | {truth} | {s} | {sc} | {vx} | {fmt(h0)} | {fmt(h1)} | "
                                f"{'<br>'.join(sorted({f'{st}' for *_, st in sup})) or '—'} | {vc_txt} | "
                                f"{'✅' if ok else ('❌ FP' if h1 else '❌ FN')} |")
    (OUT / "results.json").write_text(json.dumps(res, indent=1))
    md = ["## PyYAML identity recorded by each SBOM tool", "", "| variant | SBOM tool | PyYAML PURL(s) |",
          "|---|---|---|", *purl_rows, "", "## Findings for CVE-2020-14343 / GHSA-8q59-q68h-6hv4", "",
          "| variant | oracle | SBOM | scanner | VEX doc | without VEX | with `--vex` | suppressed as | "
          "vexctl filter (SARIF) | final vs oracle |", "|---|---|---|---|---|---|---|---|---|---|", *rows]
    (OUT / "tables.md").write_text("\n".join(md) + "\n")
    print("\n".join(md))


def probe():
    """Root-cause probes: patch one field in an SBOM, or apply a VEX to the wrong image, and re-scan."""
    p = OUT / "probe"
    p.mkdir(exist_ok=True)
    g = lambda sbom, *a: json.loads(pod(GRYPE, f"sbom:/out/{sbom}", "-q", "-o", "json", *a,
                                        mounts=[f"{CACHE}/grype:/cache:Z"],
                                        env=["GRYPE_DB_CACHE_DIR=/cache", "GRYPE_DB_AUTO_UPDATE=false"]).stdout)
    t = lambda sbom, *a: json.loads(pod(TRIVY, "sbom", "-q", "--skip-db-update", "--scanners", "vuln", "-f", "json",
                                        *a, f"/out/{sbom}", mounts=[f"{CACHE}/trivy:/root/.cache/trivy:Z"]).stdout)
    gh = lambda j: sorted({m["artifact"]["purl"].split("?")[0] for m in j["matches"]
                           if {m["vulnerability"]["id"], *[r["id"] for r in m.get("relatedVulnerabilities", [])]} & TARGET})
    th = lambda j: sorted({x["PkgIdentifier"]["PURL"].split("?")[0] for r in j.get("Results", [])
                           for x in r.get("Vulnerabilities", []) if x["VulnerabilityID"] in TARGET})

    def patched(src, name, fn):
        b = json.loads((OUT / src).read_text())
        for c in b["components"]:
            if c.get("name") == "python3-yaml":
                fn(c)
        (p / name).write_text(json.dumps(b, indent=1))
        return f"probe/{name}"

    lines = []
    # 1. Grype reads the deb source package only from the PURL 'upstream' qualifier (Syft style)
    s = patched("deb-unpatched/sbom.trivy.cdx.json", "deb-unpatched.trivy+upstream.cdx.json",
                lambda c: c.update(purl=c["purl"] + "&upstream=pyyaml"))
    lines.append(f"grype, Trivy SBOM as-is                     : {gh(g('deb-unpatched/sbom.trivy.cdx.json'))}")
    lines.append(f"grype, Trivy SBOM + purl upstream=pyyaml    : {gh(g(s))}")
    # 2. Trivy reads it only from its own property aquasecurity:trivy:SrcName (Trivy style)
    s = patched("deb-unpatched/sbom.syft.cdx.json", "deb-unpatched.syft+trivy-srcname.cdx.json",
                lambda c: c["properties"].extend([{"name": f"aquasecurity:trivy:{k}", "value": v} for k, v in
                                                  (("SrcName", "pyyaml"), ("SrcVersion", "5.3.1"), ("SrcRelease", "1"))]))
    lines.append(f"trivy, Syft SBOM as-is                      : {th(t('deb-unpatched/sbom.syft.cdx.json'))}")
    lines.append(f"trivy, Syft SBOM + trivy:SrcName=pyyaml     : {th(t(s))}")
    # 3. VEX for the patched deb applied to the (vulnerable) pypi image
    wrong = "/out/deb-patched/vex.openvex.json"
    lines.append(f"pypi image + deb-patched VEX, grype --vex   : {gh(g('pypi/sbom.syft.cdx.json', '--vex', wrong))}")
    lines.append(f"pypi image + deb-patched VEX, trivy --vex   : {th(t('pypi/sbom.syft.cdx.json', '--vex', wrong))}")
    r = sh(str(VEXCTL), "filter", str(OUT / "pypi/scan/trivy.syft.none.sarif"), str(OUT / "deb-patched/vex.openvex.json"))
    left = [x["ruleId"] for run in json.loads(r.stdout)["runs"] for x in run["results"] if x["ruleId"] in TARGET]
    lines.append(f"pypi image + deb-patched VEX, vexctl filter : {left}  (trivy SARIF)")
    # 4. How strictly does --vex match? Edited copies of the local-backport 'fixed' statement.
    vm = p / "vexmatch"
    vm.mkdir(exist_ok=True)
    for name, product, alias in (("a-no-alias", VARIANTS["local-backport"], []),
                                 ("b-plain-5.3.1", "pkg:pypi/pyyaml@5.3.1", ["--aliases", GHSA]),
                                 ("c-no-version", "pkg:pypi/pyyaml", ["--aliases", GHSA])):
        sh(str(VEXCTL), "create", "--author", "Example PSIRT", "--id", f"https://example.com/vex/probe/{name}",
           "--product", product, "--vuln", CVE, *alias, "--status", "fixed",
           "--file", str(vm / f"{name}.openvex.json"), env={**os.environ, "SOURCE_DATE_EPOCH": TS})
        for tgt in ("local-backport", "pypi"):
            arg = ("--vex", f"/out/probe/vexmatch/{name}.openvex.json")
            sb = f"{tgt}/sbom.syft.cdx.json"
            lines.append(f"VEX {name:14} on {tgt:14} SBOM: grype left {len(gh(g(sb, *arg)))}, "
                         f"trivy left {len(th(t(sb, *arg)))}")
    (p / "probes.txt").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


STAGES = {"fetch": fetch, "build": build, "evidence": evidence, "sbom": sbom, "vex": vex, "scan": scan, "report": report,
          "probe": probe}

if __name__ == "__main__":
    for st in sys.argv[1:] or STAGES:
        print(f"== {st}", file=sys.stderr)
        STAGES[st]()
