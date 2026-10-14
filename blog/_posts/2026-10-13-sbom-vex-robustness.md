---
layout: post
title: "Understanding the Robustness of SBOM and VEX Tools, and How They Affect Each Other"
date: 2026-10-13
description: One vulnerable library installed seven ways, two SBOM generators, two scanners and a correct VEX statement. Where software identity breaks, why, and how one tool's choices change another tool's answer.
tags: [SBOM, VEX, syft, grype, trivy, supply-chain-security]
categories: security
author: Jawed Khelif and Mohannad Alhanahnah
related_posts: false
toc:
  beginning: true
---

### TL;DR

We installed the same vulnerable library, PyYAML 5.3.1 (CVE-2020-14343), in seven different ways. We then generated SBOMs with Syft and Trivy, scanned each SBOM with Grype and with Trivy, and applied a correct VEX statement from the supplier. Compared with an exploit-based ground truth, 7 of the 28 scan results were wrong. VEX fixed 4 of them; the 3 that remained all came from how one tool's output is read by another. The causes are concrete: an SBOM format that drops a relationship, vendor-specific fields for a Debian source package, PURLs that forget where code came from, VEX matching that depends on exact PURL details and on each scanner's own vulnerability ID, and a VEX post-filter that ignores the product altogether. Making the SBOM from the source instead of the built image adds failure modes of its own, because the SBOM then sees only the dependency manifest. Each tool behaves reasonably on its own. Robustness breaks at the seams between them.
{: .notice--info}

## Why look at the seams?

The promise of SBOM and VEX is simple. A supplier publishes an SBOM that lists the components inside a product. A consumer's scanner matches those components against vulnerability advisories. When a match is not real, for example because the supplier backported a fix, a VEX statement says so, and the scanner suppresses the finding.

Every step in that chain assumes the tools agree on **what a component is**. In practice they are different tools from different organisations: the SBOM may come from one vendor's generator, the scan from another vendor's scanner, and the VEX statement from a third party. CISA's guidance names the problem directly: "the unique identification of products and correlation against existing inventories are difficult problems to solve at scale, as long as there is a lack of consensus around a global software identification system."[^when]

So instead of scoring each tool on its own, this experiment holds the vulnerable code fixed and varies everything around it: the install route, the SBOM generator, the scanner, and how VEX is applied. A robust pipeline should give the same answer every time. It does not.

We asked four questions:

1. Does each **SBOM generator** identify the component correctly?
2. Does each **scanner** report the vulnerability correctly?
3. Does a correct supplier **VEX statement** get applied?
4. How do the tools **affect each other**: does one tool's choice change another tool's answer?

## Methodology

The method is a controlled comparison in four steps:

1. **Hold the code fixed.** One library (PyYAML 5.3.1), one vulnerability (CVE-2020-14343), and one small service that calls the vulnerable function.
2. **Vary everything a real pipeline varies.** How the library is installed (7 routes), which tool generates the SBOM (2), which tool scans it (2), and the VEX mode: no VEX, VEX applied by the scanner (`--vex`), or VEX applied afterwards by a post-filter (`vexctl filter`). That makes 7 × 2 × 2 × 3 = 84 results.
3. **Judge every result against independent ground truth.** An oracle runs a proof of concept inside each image and decides whether that image is exploitable. No scanner output is ever used as truth.
4. **Explain every error with controlled probes.** For each wrong result, change one thing (one SBOM field, one VEX field, the SBOM format, or the image a statement is applied to), rescan, and see whether the result flips. That isolates the mechanism behind the error.

Because only the packaging changes and the code does not, any disagreement between results is a robustness failure of the tools, not a difference in risk.

{% include figure.liquid loading="eager" path="assets/img/blog/2026/sbom-vex-methodology.png" class="img-fluid rounded z-depth-1" zoomable=true %}
<div class="caption" markdown="1">
**Figure 1.** The method: hold the vulnerable code fixed, vary the pipeline around it, judge each result against an exploit-based oracle, and explain each error with one-change probes.
</div>

## The experiment

### The vulnerability

CVE-2020-14343 affects PyYAML before 5.4. `yaml.full_load()` (the `FullLoader`) still let a document build arbitrary Python objects, an incomplete fix of the earlier CVE-2020-1747. A harmless proof of concept asks the loader to evaluate `6*7`:

```python
import yaml
poc = ('!!python/object/new:tuple '
       '[!!python/object/new:map [!!python/name:eval , ["6*7"]]]')
yaml.full_load(poc)
# vulnerable: (42,)
# fixed:      ConstructorError (no constructor for python/object/new)
```

The upstream fix ([commit 7adc0db](https://github.com/yaml/pyyaml/commit/7adc0db3f613a82669f2b168edd98379b83adb3c), released in 5.4) moves three constructors from `FullLoader` to `UnsafeLoader`. It touches one file, `yaml/constructor.py`:

```diff
-FullConstructor.add_multi_constructor(
-    'tag:yaml.org,2002:python/object/new:',
-    FullConstructor.construct_python_object_new)
 ...
+UnsafeConstructor.add_multi_constructor(
+    'tag:yaml.org,2002:python/object/new:',
+    UnsafeConstructor.construct_python_object_new)
```

(The same move applies to `python/module:` and `python/object:`.)

### Seven ways to install one library

All seven images are `ubuntu:20.04` with Python 3.8.10, and all run the same small service that calls `yaml.full_load` on client data. Only the way PyYAML gets into the image changes:

| install | how PyYAML gets in | what it models |
|---|---|---|
| deb-unpatched | apt: `python3-yaml=5.3.1-1` | a distro package, before the security update |
| deb-patched | apt: `python3-yaml=5.3.1-1ubuntu0.1` | the same package after Ubuntu's security update |
| pypi | pip: `PyYAML==5.3.1` | the release from PyPI |
| git | pip: the upstream git tag `5.3.1` | a build from source control |
| local | pip: a local copy of the 5.3.1 source | a vendored source tree |
| local-backport | pip: the same tree plus Ubuntu's patch, version `5.3.1+acme1` | an organisation that backports the fix itself |
| pypi-fixed | pip: `PyYAML==6.0.2` | the control: a fixed release |

The local-backport install uses the exact patch Ubuntu applied (byte-identical to Ubuntu's `debian/patches/CVE-2020-14343.patch`) and marks the rebuild with a [PEP 440 local version label](https://peps.python.org/pep-0440/#local-version-identifiers), `+acme1`. A local label marks a rebuild without changing the public version, so `5.3.1+acme1` still falls inside the advisory's affected range `< 5.4`.

### Ground truth that does not depend on any scanner

An oracle script runs the proof of concept inside each container and records the SHA-256 of the `yaml/constructor.py` that Python actually imports. It never asks a scanner. The result is binary, and it splits the seven installs into two groups:

| code in `yaml/constructor.py` | installs | PoC |
|---|---|---|
| vulnerable, `3b751a7f…` | deb-unpatched, pypi, git, local | `(42,)` |
| fixed, `90d8247d…` | deb-patched, local-backport, pypi-fixed | `ConstructorError` |

We checked both hashes against the original artifacts: the PyPI 5.3.1 sdist and Ubuntu's `5.3.1-1` deb carry the vulnerable file; Ubuntu's `5.3.1-1ubuntu0.1` deb, the 5.3.1 tree with the patch applied, and PyYAML 6.0.2 (sdist and wheel) carry the fixed one, byte for byte. Ubuntu's patched file is identical to the one in 6.0.2.

### The pipeline

{% include figure.liquid loading="eager" path="assets/img/blog/2026/sbom-vex-pipeline.png" class="img-fluid rounded z-depth-1" zoomable=true %}
<div class="caption" markdown="1">
**Figure 2.** The supplier builds the image, generates the SBOM and writes the VEX statement, with the status taken from the oracle. The consumer scans the SBOM and applies the VEX, either inside the scanner (`--vex`) or afterwards on SARIF output (`vexctl filter`). The numbered badges mark Findings 1–5.
</div>

The pipeline uses four tools; Trivy and vexctl each play two roles:

| role | tool | what it does here |
|---|---|---|
| SBOM generator | Syft 1.54.1 | lists the packages installed in the image, as CycloneDX 1.7 JSON |
| SBOM generator | Trivy 0.75.0 (`trivy image`) | the same, with Trivy's own catalogers |
| scanner | Grype 0.120.1 | matches the SBOM's components against its vulnerability database; can apply VEX itself (`--vex`) |
| scanner | Trivy 0.75.0 (`trivy sbom`) | the same, with Trivy's database |
| VEX author | vexctl 0.4.4 (`vexctl create`) | writes the supplier's OpenVEX statement |
| VEX post-filter | vexctl 0.4.4 (`vexctl filter`) | removes findings from a scanner's SARIF report, using a VEX document |

Each scanner reads each generator's SBOM, so "Syft→Grype" means an SBOM generated by Syft and scanned by Grype. That gives 7 installs × 4 pairs = 28 results for each way of applying VEX.

**SBOMs from the image.** Each image is built and saved as an archive file (`podman save --format docker-archive`), and both generators read that file, with no registry and no running container:

```bash
syft scan docker-archive:images/pypi.tar -o cyclonedx-json=pypi.syft.cdx.json
trivy image --input images/pypi.tar --format cyclonedx \
            --output pypi.trivy.cdx.json
```

They unpack the image's layers and list what is *installed*, from the package records in its filesystem: dpkg's database for debs, and Python's installed-package metadata (`*.dist-info`, `*.egg-info`) for Python packages. They do not read the source code, the Containerfile, or a `requirements.txt`. Finding 6 shows what changes when the SBOM is made from the source instead.

**Two ways to apply VEX.** A scanner can apply the VEX document itself (`grype --vex`, `trivy --vex`): it suppresses each finding an applicable `fixed` or `not_affected` statement covers, before it writes its report. Or a *post-filter* applies it afterwards: the scanner writes its findings as SARIF (the Static Analysis Results Interchange Format, the standard JSON format for the results of analysis tools), and `vexctl filter` removes the findings that the VEX document marks `fixed` or `not_affected`. Pipelines that collect SARIF reports, or whose scanner cannot read VEX, use the second route. We ran both.

- **VEX statement:** written with vexctl as a supplier would write it. The status comes from the oracle (`affected` or `fixed`), the product is the PURL the supplier knows it shipped, and the statement lists both IDs, `CVE-2020-14343` and its GitHub alias `GHSA-8q59-q68h-6hv4`.
- **Reproducibility:** all tool images and the base image are pinned by digest, and the vulnerability databases are frozen. Re-scanning every SBOM five days later, with newer databases, gave identical results, and a fresh clone of the pipeline reproduced every result end to end.

## What the SBOMs say

{% include figure.liquid loading="lazy" path="assets/img/blog/2026/sbom-vex-identities.png" class="img-fluid rounded z-depth-1" zoomable=true %}
<div class="caption" markdown="1">
**Figure 3.** Seven installs, five PURLs in Syft's SBOMs, two versions of the vulnerable file. `pkg:pypi/pyyaml@5.3.1` is shared by five installs, including the patched deb (red link).
</div>

Figure 3 is the root of almost everything that follows. Tools match on identity (the PURL), but identity and code diverge in both directions:

- **Different identities, same code.** Ubuntu's patched deb, the backport and 6.0.2 contain the same fixed file under three different identities.
- **Same identity, different code.** `pkg:pypi/pyyaml@5.3.1` names the vulnerable PyPI release, but Syft also gives it to the patched deb.

## Results at a glance

{% include figure.liquid loading="lazy" path="assets/img/blog/2026/sbom-vex-verdicts.png" class="img-fluid rounded z-depth-1" zoomable=true %}
<div class="caption" markdown="1">
**Figure 4.** Verdict of each scan against the oracle: ✓ agrees, **FP** reported but not vulnerable, **FN** vulnerable but not reported. The table below has the same data.
</div>

| install (truth) | Syft→Grype | Syft→Trivy | Trivy→Grype | Trivy→Trivy |
|---|---|---|---|---|
| deb-unpatched (vulnerable) | ✓ / ✓ | ✓ / ✓ | FN / FN | ✓ / ✓ |
| deb-patched (not) | FP / FP | FP / FP | ✓ / ✓ | ✓ / ✓ |
| pypi, git, local (vulnerable) | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ |
| local-backport (not) | FP / ✓ | FP / ✓ | FP / ✓ | FP / ✓ |
| pypi-fixed (not) | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ |

*Each cell: without VEX / with the supplier's VEX applied by `--vex`.*

Three observations frame the rest of the post:

- **Installs from PyPI, git or a local tree are never wrong.** All errors come from the Debian packages and from the backport.
- **VEX fixes exactly the case it was designed for.** The backport carries a fix that a version-based scanner cannot see, and the supplier's statement suppresses the finding in all four pairs.
- **The three errors VEX cannot fix are interaction errors.** Each one depends on which tool generated the SBOM and which tool read it.

A caution on the numbers: the 28 cells are not independent samples, and the count depends on which installs we chose. Read them as a description of mechanisms, not as an error rate. Note also that a VEX statement with status `affected` cannot change a scan's output, so VEX was really exercised on the three non-vulnerable installs, plus the probes described below.

## Finding 1: one install, two components, and the SBOM format decides

{% include figure.liquid loading="lazy" path="assets/img/blog/2026/sbom-vex-duplicate.png" class="img-fluid rounded z-depth-1" zoomable=true %}
<div class="caption" markdown="1">
**Figure 5.** The patched deb contains Python packaging metadata that still says `Version: 5.3.1`. Syft reports it as a second component. Whether that becomes a false positive depends on the SBOM format.
</div>

**What is in the image.** Ubuntu's `python3-yaml 5.3.1-1ubuntu0.1` contains the fixed `constructor.py`. It also contains `PyYAML-5.3.1.egg-info`, the Python packaging metadata written from PyYAML's own `setup.py` when Debian built the package.

**Why the metadata looks unpatched.** Ubuntu records its fix only in the Debian revision, the `-1ubuntu0.1` after the upstream version. Python metadata has a single `Version` field, holding the upstream version, and a backport does not change it:

```text
dpkg:                python3-yaml 5.3.1-1ubuntu0.1   ← the fix shows here
importlib.metadata:  PyYAML       5.3.1              ← and not here
```

**What Syft records.** Syft's dpkg cataloger reports the deb, and its Python cataloger reads the egg-info and reports `pkg:pypi/pyyaml@5.3.1`. A scanner treats a `pkg:pypi` component as a package from PyPI, looks it up in the PyPI advisory (GHSA-8q59-q68h-6hv4, affected `< 5.4`), and reports the CVE on a patched system.

**Why the format matters.** Syft does know that the second component belongs to the deb. In its own JSON format it records (abridged):

```json
{
  "parent": "pkg:deb/ubuntu/python3-yaml@5.3.1-1ubuntu0.1?arch=amd64&...",
  "child": "pkg:pypi/pyyaml@5.3.1",
  "type": "ownership-by-file-overlap",
  "metadata": {
    "files": ["/usr/lib/python3/dist-packages/PyYAML-5.3.1.egg-info"]
  }
}
```

Grype uses that relationship. On distributions whose feed also lists unfixed vulnerabilities, Ubuntu included, Grype drops a language package that an OS package owns before matching. CycloneDX's `dependencies` section only expresses "depends on", and Syft's CycloneDX output leaves the ownership relationship out. The same image, scanned by the same Grype, gives:

| what Grype reads (deb-patched) | finding |
|---|---|
| the image itself | none |
| Syft JSON SBOM | none |
| Syft SPDX SBOM (the relationship becomes `OTHER`, with a comment) | none |
| **Syft CycloneDX SBOM** | **false positive on `pkg:pypi/pyyaml@5.3.1`** |

Trivy behaves differently in each role. As an SBOM generator it never lists the PyPI entry: it skips Python packages whose files dpkg owns. As a scanner it does not use Syft's relationship, so it reports the false positive from Syft's SPDX as well as from its CycloneDX.

**Why VEX cannot repair it.** The supplier's statement names what the supplier shipped, `pkg:deb/ubuntu/python3-yaml@5.3.1-1ubuntu0.1…`. The false positive sits on `pkg:pypi/pyyaml@5.3.1`. As Finding 4 shows, a statement for that PURL would also hide the real vulnerability in every image that contains the actual PyPI release.

## Finding 2: Debian source packages, recorded in vendor dialects

Debian and Ubuntu build *binary* packages (`python3-yaml`) from *source* packages (`pyyaml`), and Ubuntu's security data lists CVE-2020-14343 under the source package. A scanner therefore has to know that `python3-yaml` comes from `pyyaml`; looking up `python3-yaml` finds nothing. Each generator records that link in its own way:

| SBOM | where the source package is recorded |
|---|---|
| Syft, CycloneDX | PURL qualifier `upstream=pyyaml`, and property `syft:metadata:source=pyyaml` |
| Trivy, CycloneDX | property `aquasecurity:trivy:SrcName=pyyaml` |
| Trivy, SPDX | free text: `"sourceInfo": "built package from: pyyaml 5.3.1-1"` |

To find out what each scanner actually reads, we edited one field at a time in the deb-unpatched SBOMs and re-scanned:

| SBOM and edit | scanner | finds the deb? |
|---|---|---|
| Trivy SBOM, unchanged | Grype | no (false negative) |
| Trivy SBOM + `&upstream=pyyaml` in the PURL | Grype | yes |
| Trivy SBOM + Syft's properties `syft:package:metadataType` and `syft:metadata:source` | Grype | yes |
| Syft SBOM, `upstream` qualifier removed, property kept | Grype | yes |
| Syft SBOM, property removed, qualifier kept | Grype | yes |
| Syft SBOM, both removed | Grype | no |
| Syft SBOM, unchanged | Trivy | no |
| Syft SBOM + `aquasecurity:trivy:SrcName=pyyaml` | Trivy | yes |

Grype understands either of Syft's two encodings; Trivy understands only its own property; and neither reads the other vendor's field or SPDX's free text. Trivy does warn about this: "Third-party SBOM may lead to inaccurate vulnerability detection".

The consequences show up directly in Figure 4. Trivy's SBOM read by Grype misses the vulnerable deb entirely. Syft's SBOM read by Trivy misses the deb too, and is scored correct only because Syft's PyPI duplicate (Finding 1) happens to carry the CVE. **One tool's defect hides another's**: if Syft dropped the duplicate as Trivy's generator does, that cell would become a false negative.

## Finding 3: the PURL forgets where code came from

pip records where a package came from in `direct_url.json` ([PEP 610](https://peps.python.org/pep-0610/)): the git URL and commit, or `file:///src/pyyaml` for a local tree. What survives into the SBOM:

| install | Syft | Trivy |
|---|---|---|
| git | PURL `?vcs_url=git+https://…@538b5c9…`, plus an external reference with the commit | `pkg:pypi/pyyaml@5.3.1` only |
| local | external reference `file:///src/pyyaml` (typed as `vcs`) | `pkg:pypi/pyyaml@5.3.1` only |

Matching and VEX use the PURL, and there pypi and local (and, in Trivy's SBOM, git) are all `pkg:pypi/pyyaml@5.3.1`. In this experiment that changes no verdict, because the code really is the same. It matters as soon as a git or local build differs from the release with the same version: a patched or forked tree is indistinguishable from the release unless its version changes, which is exactly why the backport carries `+acme1`.

## Finding 4: how a VEX statement finds its target, and where it leaks

Both scanners apply a statement to a finding when two things match: the vulnerability, and the product. Here is the supplier's statement for the backport:

```json
{
  "vulnerability": {
    "name": "CVE-2020-14343",
    "aliases": ["GHSA-8q59-q68h-6hv4"]
  },
  "products": [{ "@id": "pkg:pypi/pyyaml@5.3.1%2Bacme1" }],
  "status": "fixed"
}
```

As a negative control, we applied the patched deb's statement to the vulnerable pypi image. Both scanners correctly ignored it, because no component in that image matches its product. To see *how* matching works, we then changed one field of the backport's statement at a time and applied each copy to the image where `fixed` is true (local-backport) and to a vulnerable image (pypi):

{% include figure.liquid loading="lazy" path="assets/img/blog/2026/sbom-vex-reach.png" class="img-fluid rounded z-depth-1" zoomable=true %}
<div class="caption" markdown="1">
**Figure 6.** Verdict after applying each statement. An FP on local-backport means the statement was not applied; an FN on pypi means the statement leaked onto a real vulnerability.
</div>

From these probes, plus two more on PURL qualifiers, the observed rules are:

1. **Vulnerability ID.** The statement's name or one of its aliases must equal the ID the scanner gives the finding. Grype keys this PyPI finding by the GHSA ID, Trivy by the CVE, and neither uses its own CVE↔GHSA link. A CVE-only statement is missed by Grype (row a); a GHSA-only statement is missed by Trivy (row d).
2. **Version.** If the product has a version, it must be equal; there are no ranges, so `5.3.1` does not match `5.3.1+acme1` (row b). A product without a version matches every version (row c).
3. **Qualifiers.** Every qualifier in the statement's PURL must be on the component (row e). Qualifiers that only the component has are ignored: a statement for `pkg:pypi/pyyaml@5.3.1` also applies to the git install's `…@5.3.1?vcs_url=…`.

Two consequences matter in practice:

- **Leaks.** A statement whose product is a package applies to that package in every SBOM it meets. The backport's statement stays contained only because its rebuild has its own version. A backport that kept `5.3.1`, or the patched deb's PyPI duplicate from Finding 1, could only be covered by a statement for `pkg:pypi/pyyaml@5.3.1`, and that statement hides the real vulnerability in the pypi image (row b).
- **Cross-tool misses.** The qualifier rule turns SBOM dialects into VEX failures. A `fixed` statement for the deb written the way Syft writes the PURL (`…?arch=amd64&distro=ubuntu-20.04&upstream=pyyaml`) is applied by Grype to Syft's SBOM, but not by Trivy to Trivy's SBOM, which has no `upstream` qualifier. A supplier who copies the PURL from its own Syft SBOM writes a statement that consumers using Trivy SBOMs cannot apply.

CISA's minimum requirements say that a statement's product and subcomponent identifiers "SHOULD reference existing SBOM identifiers".[^minreq] This experiment shows why that is harder than it sounds: the "existing SBOM identifier" depends on which tool wrote the SBOM, and scanners match on exactly those differences.

## Finding 5: a post-filter that ignores the product

Not every pipeline applies VEX inside the scanner. A common alternative is to scan first and filter the SARIF report afterwards with `vexctl filter`. In vexctl 0.4.4 that filter never looks at products:

```go
// vexctl v0.4.4, ApplySingleVEX (abridged; comments ours)
statements := vexDoc.StatementsByVulnerability(id)   // id = the SARIF rule ID
if len(statements) == 0 {
    newResults = append(newResults, res)              // no statement: keep
    continue
}
switch statements[0].Status {
case vex.StatusNotAffected, vex.StatusFixed:
    // dropped: no product check anywhere
default:
    newResults = append(newResults, res)
}
```

The effects are easy to demonstrate:

- **Product-blind removal.** The patched deb's statement, applied to the vulnerable pypi image's Trivy SARIF, removed the true finding. So did a statement about an unrelated package, `pkg:npm/left-pad@1.0.0`.
- **Missed GHSA rules.** Grype names its SARIF rules `<ID>-<package>` (here `GHSA-8q59-q68h-6hv4-pyyaml`), and vexctl strips that suffix only from CVE IDs. So it never removes Grype's PyPI findings, even when it should: the backport stays flagged in both Grype pairs.
- **Right for the wrong reason.** In the matrix, the deb statement removed Syft→Trivy's false positive on the PyPI duplicate. A product-blind filter hid one of the errors, by accident.

Note that this is not because SARIF lacks product information. Grype's SARIF includes the PURL in its rule properties; vexctl simply does not read it.

## Finding 6: an SBOM made from the source sees the manifest, not the install

Every SBOM so far was made from the built image. Many pipelines make it earlier, from the source tree, where the only evidence is a dependency manifest. We added a `requirements.txt` next to `app.py` in five installs and made SBOMs both ways (`syft dir:` and `trivy fs` for the source directory):

| install (truth) | `requirements.txt` | SBOM from the image | SBOM from the source directory |
|---|---|---|---|
| pypi (vulnerable) | `PyYAML==5.3.1` | ✓ | ✓ |
| pypi-fixed (not) | `PyYAML==5.3.1`, stale: 6.0.2 is installed | ✓ | **FP** |
| deb-patched (not) | `PyYAML==5.3.1`, though apt provides it | as in Figure 4 | **FP**, for both generators |
| git (vulnerable) | `PyYAML @ git+https://github.com/yaml/pyyaml.git@5.3.1` | ✓ | **FN**: neither generator records the git reference |
| local-backport (not) | `PyYAML==5.3.1`, the public version over the patched build | ✓ with VEX | **FP** that the backport's VEX cannot reach |

*Verdicts with the supplier's VEX applied; Grype and Trivy agree in every cell.*

- **From the image, the manifest is ignored.** Both generators list what is installed, so the `requirements.txt` changed no SBOM and no verdict.
- **From the source, the manifest is all there is.** A stale pin becomes a false positive. A dependency installed another way (apt), or written in a form the parser skips (a git reference), disappears. A patched build is recorded at its public version, `pkg:pypi/pyyaml@5.3.1`, which the supplier's statement for `5.3.1+acme1` does not match.
- **Mixing the two views duplicates the package.** With Syft's manifest cataloger switched on for the image, the declared `pyyaml@5.3.1` sits next to the installed version as a separate component, and both scanners report it.

## How the tools affect each other

Put together, the verdict for a single, unchanged piece of code depends on a chain of choices made by different tools:

| choice | example of its effect |
|---|---|
| **SBOM generator** | Syft lists the deb's Python metadata as a second component; Trivy does not. |
| **SBOM format** | Syft's relationship survives in Syft JSON and SPDX, but not in CycloneDX; Grype's answer flips with it. |
| **Scanner** | Grype reads only Syft's source-package fields, Trivy only its own: the same SBOM gives a false negative in one and not the other. |
| **VEX author** | A statement copied from a Syft SBOM's PURL is not applied by Trivy to Trivy's SBOM. |
| **VEX ID choice** | CVE-only and GHSA-only statements each miss one of the two scanners. |
| **VEX application** | `--vex` checks the product; `vexctl filter` does not. |
| **Where the SBOM is made** | From the image, a `requirements.txt` is ignored; from the source directory, it is all the SBOM sees. |

Two interaction patterns stand out.

- **Defects mask each other.** Syft's duplicate component makes Syft→Trivy look correct on the vulnerable deb, hiding Trivy's inability to read Syft's source-package fields. Fixing one defect alone would expose the other.
- **Correctness is a property of the pair, not the tool.** Trivy→Trivy is correct on both debs, and so is Syft→Grype read from Syft's own JSON. The failures appear when one vendor's output is the other vendor's input, or when a lossy format sits between them. That is exactly the situation SBOM sharing is meant to support.

## What this means in practice

**For SBOM generator authors**
- Keep containment and ownership relationships in every output format. CycloneDX can express "this Python package is part of that deb" through nested components or a property; dropping it changes downstream verdicts.
- Agree on one encoding for a deb's source package. Today it is a PURL qualifier for one vendor, a vendor property for another, and free text in SPDX.

**For scanner authors**
- Read the other vendors' source-package fields, or at least warn, as Trivy does, when an SBOM lacks the fields the scanner relies on.
- Use your own alias data (CVE↔GHSA) when matching VEX statements.

**For VEX authors**
- List every ID a consumer's scanner might use (CVE and GHSA).
- Give a backport its own version, for example a local label like `+vendor1`, so a statement can name it without naming the upstream release.
- Scope statements to your product (the image) with the package as a subcomponent, rather than to the package alone. We could not test this here, because the SBOMs give a locally scanned image no PURL; it is the next experiment.
- Remember that qualifiers in your PURL must appear in the consumer's SBOM. Fewer qualifiers apply more widely.

**For consumers**
- Make SBOMs from the built artifact. An SBOM made from the source tree reflects the manifest, not what is installed.
- Apply VEX inside the scanner, which checks products, rather than with a product-blind post-filter.
- Treat a generator/scanner pair from different vendors as untested until you have checked it on a known case.
- Keep the SBOM in a format that preserves relationships, or rescan from the image when the format is lossy.

## Threats to validity

- **Scope.** One CVE, one ecosystem (Python), one distribution (Ubuntu 20.04, now past standard support), and one version of each tool. The mechanisms look general, but we tested only this configuration.
- **VEX coverage.** `affected` statements cannot change a scan, so VEX application was exercised on three installs and in targeted probes. Image-scoped statements (image as product, package as subcomponent) were not tested.
- **Counting.** The "7 of 28" and "3 of 28" figures describe this design; the cells are not independent and should not be read as rates.
- **Ground truth.** The oracle tests one exploit path. For this CVE that is adequate: the fix removes exactly the constructors the exploit uses, and the oracle also records which constructors are registered.

## Reproduce it

Everything is in [JK-code505/sbom-install-sources-vex](https://github.com/JK-code505/sbom-install-sources-vex): a single Python script that drives pinned container images, plus the committed SBOMs, VEX documents, probes and the raw scanner output of the reported run. On a Linux host with podman:

```bash
python3 -I run.py          # all stages, from fetch to probe
```

The first run downloads about 5 GB of vulnerability databases and builds seven images; afterwards the databases are reused unchanged. The archived raw scanner output of the run reported here can be re-tabulated without any containers:

```bash
tar -xJf out/scans-2026-10-08.tar.xz && python3 -I run.py report
```

## Credits

This experiment was led by **Jawed Khelif**, who deserves most of the credit for it, together with Mohannad Alhanahnah. The code and data are in [JK-code505/sbom-install-sources-vex](https://github.com/JK-code505/sbom-install-sources-vex).

## References

[^when]: CISA, [When to Issue VEX Information](https://www.cisa.gov/sites/default/files/2023-11/When-to-Issue-a-VEX-508c.pdf) (2023).
[^minreq]: CISA, [Minimum Requirements for Vulnerability Exploitability eXchange (VEX)](https://www.cisa.gov/sites/default/files/2023-04/minimum-requirements-for-vex-508c.pdf) (2023), §2.5.

- CISA, [VEX Status Justifications](https://www.cisa.gov/sites/default/files/publications/VEX_Status_Justification_Jun22.pdf) (2022).
- [OpenVEX specification](https://github.com/openvex/spec) and [vexctl](https://github.com/openvex/vexctl).
- [Syft](https://github.com/anchore/syft), [Grype](https://github.com/anchore/grype), [Trivy](https://github.com/aquasecurity/trivy).
- [GHSA-8q59-q68h-6hv4](https://github.com/advisories/GHSA-8q59-q68h-6hv4) and [Ubuntu's CVE-2020-14343 page](https://ubuntu.com/security/CVE-2020-14343).
- [Package URL specification](https://github.com/package-url/purl-spec), [PEP 440](https://peps.python.org/pep-0440/), [PEP 610](https://peps.python.org/pep-0610/).
