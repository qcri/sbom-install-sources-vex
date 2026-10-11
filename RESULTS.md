# One library, seven installs: SBOM → scanner → VEX

**Question.** The same PyYAML 5.3.1 code (CVE-2020-14343) is installed in different ways. Does the SBOM identify it correctly, does the scanner flag it correctly, and does a correct supplier VEX statement get applied?

**Run it:** `python3 -I run.py` (stages: `fetch build evidence sbom vex scan report probe`). Raw scan output from the run reported here: `out/scans-2026-10-08.tar.xz`. Tool versions are in `out/versions.txt`: Syft 1.54.1, Grype 0.120.1 (DB built 2026-10-08), Trivy 0.75.0 (DB 2026-10-07), vexctl v0.4.4.

## Setup

One image per variant (`variants/<name>/Containerfile`). All images are `ubuntu:20.04` with Python 3.8.10, and they all contain the same `app/app.py`, which calls `yaml.full_load` on client data. Open any of them with `podman run -it vexlab/<name>:1.0 bash`.

| variant | how PyYAML is installed |
|---|---|
| deb-unpatched | `apt install python3-yaml=5.3.1-1` (original 20.04 release) |
| deb-patched | `apt install python3-yaml=5.3.1-1ubuntu0.1` (Ubuntu security update) |
| pypi | venv, `pip install PyYAML==5.3.1` (sdist from PyPI; sha256 verified) |
| git | venv, `pip install git+https://github.com/yaml/pyyaml.git@5.3.1` |
| local | venv, `pip install ./pyyaml-5.3.1` (unmodified sdist tree) |
| local-backport | venv, same tree plus **Ubuntu's own `CVE-2020-14343.patch`** (= upstream commit 7adc0db), version set to `5.3.1+acme1` |
| pypi-fixed | venv, `pip install PyYAML==6.0.2` (control) |

## 1. Ground truth (`out/<variant>/evidence.txt`)

`app/oracle.py` runs the public PoC with a harmless payload. A result of `(42,)` means exploitable.

| variant | metadata version | dpkg version | `constructor.py` sha256 | PoC | truth |
|---|---|---|---|---|---|
| deb-unpatched | 5.3.1 (egg-info) | 5.3.1-1 | `3b751a7f…` | `(42,)` | **vulnerable** |
| deb-patched | **5.3.1** (egg-info) | 5.3.1-1ubuntu0.1 | `90d8247d…` | ConstructorError | not vulnerable |
| pypi | 5.3.1 | – | `3b751a7f…` | `(42,)` | **vulnerable** |
| git | 5.3.1 (`direct_url.json`: commit 538b5c9) | – | `3b751a7f…` | `(42,)` | **vulnerable** |
| local | 5.3.1 (`direct_url.json`: `file:///src/pyyaml`) | – | `3b751a7f…` | `(42,)` | **vulnerable** |
| local-backport | 5.3.1+acme1 (`yaml.__version__` still `5.3.1`) | – | `90d8247d…` | ConstructorError | not vulnerable |
| pypi-fixed | 6.0.2 | – | `90d8247d…` | ConstructorError | not vulnerable |

Checksums agree everywhere: pip's `RECORD` matches every installed file, and `dpkg --verify` matches the deb's md5sums. The only `dpkg --verify` warning is `/usr/share/doc/README`, which the minimal Ubuntu image strips.

**There are only two versions of the code.** Ubuntu's patched `constructor.py` is byte-for-byte identical to PyYAML 6.0.2's. Yet in deb-patched the Python metadata says `5.3.1`, and only the dpkg database knows the package is fixed.

## 2. What each SBOM records (`out/<variant>/sbom.{syft,trivy}.cdx.json`)

| variant | Syft | Trivy |
|---|---|---|
| deb-* | **two** components: `pkg:deb/ubuntu/python3-yaml@<rev>?…&upstream=pyyaml` **and** `pkg:pypi/pyyaml@5.3.1` | one: `pkg:deb/ubuntu/python3-yaml@<rev>?arch=amd64&distro=ubuntu-20.04` |
| pypi | `pkg:pypi/pyyaml@5.3.1` | `pkg:pypi/pyyaml@5.3.1` |
| git | `pkg:pypi/pyyaml@5.3.1?vcs_url=git+https://github.com/yaml/pyyaml.git@538b5c9…` | `pkg:pypi/pyyaml@5.3.1` (origin lost) |
| local | `pkg:pypi/pyyaml@5.3.1` (origin lost) | `pkg:pypi/pyyaml@5.3.1` (origin lost) |
| local-backport | `pkg:pypi/pyyaml@5.3.1%2Bacme1` | `pkg:pypi/pyyaml@5.3.1%2Bacme1` |
| pypi-fixed | `pkg:pypi/pyyaml@6.0.2` | `pkg:pypi/pyyaml@6.0.2` |

Neither tool puts a PURL on the SBOM root (the image), because a local image archive has no registry digest.

## 3. Scanner results for CVE-2020-14343 / GHSA-8q59-q68h-6hv4, with the supplier VEX applied (`--vex`)

The VEX author is "Example PSIRT" (`vexctl create`). The status comes from the oracle, the product is the PURL the supplier knows it shipped, and the statement lists both the CVE and the GHSA ID. Full table: `out/tables.md`; raw results: `out/<variant>/scan/`.

| variant (truth) | Syft→Grype | Syft→Trivy | Trivy→Grype | Trivy→Trivy |
|---|---|---|---|---|
| deb-unpatched (vuln) | ✅ | ✅ *only via the duplicate pypi entry; the deb entry is missed* | ❌ **FN** | ✅ |
| deb-patched (not) | ❌ **FP** on `pkg:pypi/pyyaml@5.3.1`; VEX can't reach it | ❌ **FP**, same | ✅ *only because Grype can't match the deb at all* | ✅ |
| pypi (vuln) | ✅ | ✅ | ✅ | ✅ |
| git (vuln) | ✅ (matched despite `vcs_url`) | ✅ | ✅ | ✅ |
| local (vuln) | ✅ | ✅ | ✅ | ✅ |
| local-backport (not) | FP → ✅ after VEX | FP → ✅ after VEX | FP → ✅ after VEX | FP → ✅ after VEX |
| pypi-fixed (not) | ✅ | ✅ | ✅ | ✅ |

For local-backport, `fixed` and `not_affected/vulnerable_code_not_present` were both applied by both scanners. The scanners treat them identically, so the choice between them only matters to the people reading the VEX.

## 4. Why the errors happen (`out/probe/probes.txt`, `python3 -I run.py probe`)

1. **Syft lists a deb-installed Python package twice.** It records both the deb and the egg-info, and the egg-info entry `pkg:pypi/pyyaml@5.3.1` hides the Ubuntu revision. Scanners match that entry against the PyPI advisory (`< 5.4`), so the patched deb gets a false positive. The supplier's VEX names the deb PURL, so it never touches that finding. Trivy skips Python files owned by dpkg, so it doesn't have this problem.
2. **Each scanner reads the deb source-package name only in its own vendor's format.** Ubuntu files the CVE under the source package `pyyaml`, not `python3-yaml`.
   - Grype reads it only from the PURL qualifier `upstream=pyyaml`, which Syft writes. On Trivy's SBOM it misses the CVE; adding the qualifier fixes it.
   - Trivy reads it only from its own property `aquasecurity:trivy:SrcName`. On Syft's SBOM it misses the deb CVE; adding the property fixes it. Trivy also warns: "Third-party SBOM may lead to inaccurate vulnerability detection".
3. **Install origin disappears.** A git install keeps its origin only in Syft's PURL (`vcs_url`). A local install keeps it in neither tool. Both are recorded on disk in `direct_url.json`.
4. **`--vex` matches on the PURL; the post-filter matches on the CVE ID only.**
   - When I applied deb-patched's `fixed` VEX to the vulnerable pypi image, `grype --vex` and `trivy --vex` correctly ignored it.
   - `vexctl filter` on Trivy's SARIF **removed the true finding (FN)**, because Trivy's SARIF has no PURL to compare.
   - On Grype's SARIF, `vexctl` removes nothing, because the rule ID is `GHSA-8q59-q68h-6hv4-pyyaml`, with the package name appended.

5. **How strict `--vex` matching is.** I edited copies of the local-backport `fixed` statement and counted findings left after `--vex` (0 = suppressed):

   | edited statement | local-backport (safe) | pypi (vulnerable) |
   |---|---|---|
   | (a) CVE only, no GHSA alias | Grype 1, Trivy 0 | Grype 1, Trivy 1 |
   | (b) product `pkg:pypi/pyyaml@5.3.1` | Grype 1, Trivy 1 | **Grype 0, Trivy 0** (real finding hidden) |
   | (c) product `pkg:pypi/pyyaml` (no version) | Grype 0, Trivy 0 | **Grype 0, Trivy 0** (real finding hidden) |

   - The ID must match literally. Grype reports the GHSA ID and does not use its own CVE link when matching VEX.
   - The version must match exactly.
   - A statement whose product is just the package applies to *every* SBOM that contains that PURL.
   - local-backport is suppressed correctly only because its rebuild carries its own version (`+acme1`).

## 5. Mapping to CISA (findings 1–5 above)

- **"[product_id] and [subcomponent_id] SHOULD reference existing SBOM identifiers"** (Minimum Requirements §2.5). Findings 1–2 show that the "existing SBOM identifier" depends on which tool wrote the SBOM. The supplier's correct deb PURL misses Syft's pypi duplicate.
- **"correlation against existing inventories [is] difficult … as long as there is a lack of consensus around a global software identification system"** (When to Issue VEX). This is reproduced directly by findings 1–3.
- **"VEX consumers should … deconflict VEX information for multiple occurrences of the same upstream component"** (When to Issue VEX). The Syft duplicate is exactly such a second occurrence.
- **Tools "should sufficiently validate the accuracy of VEX information"** (When to Issue VEX). The product-blind post-filter in finding 4 is what happens when they don't.
- **Backport: `fixed` vs `vulnerable_code_not_present`.** Scanners treat both the same. The evidence (identical code to 6.0.2, produced by a patch) fits CISA's `fixed` ("contain fixes for [vul_id]") better than vcnp, whose CISA examples are code that was stripped or never added.

## Limits / next steps

- The supplier VEX uses the **package as the product**. A VEX scoped to the image (image as product, package as subcomponent, as CISA frames it) can't be tested here, because neither SBOM gives the image root a PURL. Pushing the images to a local registry would give them digests and allow that test.
- One CVE, one ecosystem, one version of each tool. Results are from 2026-10-08.
- Not yet run: cve-bin-tool and Dependency-Track (CycloneDX VEX path).
