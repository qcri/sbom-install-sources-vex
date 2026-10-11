# Same library, seven installs: what SBOMs, scanners and VEX miss

**Question.** Install the same vulnerable library (PyYAML 5.3.1, CVE-2020-14343) in different ways: Ubuntu apt, PyPI, git, a local source tree, and a local backport. Then ask three things:
1. Does each SBOM tool identify the component correctly?
2. Does each scanner report the vulnerability correctly?
3. Does a correct supplier VEX statement actually get applied?

**Short answer.** Not reliably. The tool pairing, the install method and the exact PURL decide the outcome more than the actual code does. Details are in **[RESULTS.md](RESULTS.md)**; how to continue the work is in **[HANDOFF.md](HANDOFF.md)**.

## Design

```
SUPPLIER ("Example PSIRT")                      CONSUMER
 build image ─► SBOM (Syft | Trivy) ─────────────► SBOM ─┐
      └─► oracle.py (PoC in the container) ─► VEX ─► VEX ─┴─► scanner (Grype | Trivy) ─► findings
                                     (vexctl create)            --vex  or  vexctl filter on SARIF
```

- **7 images, all `ubuntu:20.04` / Python 3.8.10.** Only the install method differs:

  | variant | install |
  |---|---|
  | deb-unpatched | `apt install python3-yaml=5.3.1-1` |
  | deb-patched | `apt install python3-yaml=5.3.1-1ubuntu0.1` (Ubuntu security fix) |
  | pypi | `pip install PyYAML==5.3.1` |
  | git | `pip install git+https://github.com/yaml/pyyaml.git@5.3.1` |
  | local | `pip install ./pyyaml-5.3.1` |
  | local-backport | same + Ubuntu's CVE patch, version `5.3.1+acme1` |
  | pypi-fixed | `pip install PyYAML==6.0.2` (control) |
- **Ground truth** is `app/oracle.py`. It runs the public PoC with a harmless payload inside each container, so it never relies on a scanner.
- **VEX** is written as the supplier would write it (`vexctl create`): the status comes from the oracle, and the product is the PURL the supplier knows it shipped.
- **Consumers:** Grype 0.120.1 and Trivy 0.75.0, each reading both Syft (1.54.1) and Trivy SBOMs. Each scan runs without VEX, with `--vex`, and with `vexctl filter` applied to SARIF output.

## Headline results

1. **Syft lists a deb-installed Python package twice:** once as the deb and once as `pkg:pypi/pyyaml@5.3.1`. On the patched Ubuntu deb, that produces a false positive that the supplier's correct deb VEX can't reach.
2. **Each scanner reads the deb source package only in its own vendor's format.**
   - Grype reads it from the PURL `upstream=` qualifier, which Syft writes.
   - Trivy reads it from its own `aquasecurity:trivy:SrcName` property.

   So a Trivy SBOM fed to Grype misses the vulnerable deb (false negative), and a Syft SBOM fed to Trivy misses the deb entry.
3. **The install origin is lost.** Git origin survives only in Syft's `vcs_url`, and local installs look identical to PyPI.
4. **`--vex` matching is exact on PURL and vulnerability ID.**
   - The backport was suppressed correctly only because its rebuild carries its own version, `+acme1`.
   - A statement for `pyyaml@5.3.1`, or for `pyyaml` with no version, also hides the real vulnerability in other images.
5. **`vexctl filter` on SARIF ignores the product.** A VEX statement for a different package removed a real Trivy finding.
6. **Ubuntu's patched `constructor.py` is byte-for-byte identical to PyYAML 6.0.2's**, yet its Python metadata still says `5.3.1`.

With VEX applied, **3 of the 28** scanner results are still wrong compared with the oracle (7 of 28 without VEX).

## Run it

Requirements:
- Linux with `podman`, `curl` and `patch`;
- Python ≥ 3.12 on the host (only to drive the script);
- network access on the first run.

```bash
python3 -I run.py                    # everything: fetch build evidence sbom vex scan report probe
podman run -it vexlab/git:1.0 bash   # inspect any variant; /app/evidence.sh prints what we collect

# or just look at the reported run without rebuilding:
tar -xJf out/scans-2026-10-08.tar.xz && python3 -I run.py report
```

## Layout

```
run.py                   whole pipeline, one function per stage
app/                     app.py (product), oracle.py (ground truth), evidence.{sh,py}
variants/<name>/         one Containerfile per install method
src/patches/             Ubuntu's CVE-2020-14343.patch (= upstream commit 7adc0db)
out/<variant>/           evidence.txt, sbom.{syft,trivy}.cdx.json, *.openvex.json
out/tables.md            full 28-row scanner matrix;  out/results.json
out/probe/               root-cause probes (probes.txt) and VEX-matching probes
out/scans-2026-10-08.tar.xz   raw scanner JSON + SARIF of the reported run
out/versions.txt         tool, vulnerability-DB and base-image versions
```
