# Handoff

Status, decisions and next steps for whoever continues this experiment. Read [README.md](README.md) first, then [RESULTS.md](RESULTS.md).

## Status (last run 2026-10-08)

- Done: 7 variants × 2 SBOM tools × 2 scanners, each without VEX, with `--vex`, and with a `vexctl filter` post-filter. Root causes are confirmed by probes (`run.py probe`).
- The supplier VEX uses the **package as the product**. An image-scoped VEX (image = product, package = subcomponent, as CISA frames it) is **not tested yet**, because neither SBOM gives the image root a PURL when scanning a local image archive.
- The committed `out/` is a snapshot of that run. The raw scans are in `out/scans-2026-10-08.tar.xz`; `out/*/scan/` is git-ignored.

## Decisions taken (and why)

- **One base image for all variants (`ubuntu:20.04`, Python 3.8).** Ubuntu 20.04 is the only release that ships both the unpatched (`5.3.1-1`) and patched (`5.3.1-1ubuntu0.1`) `python3-yaml`. Keeping every variant on it leaves the install method as the only difference. PyYAML 5.3.1 also builds and is exploitable on Python 3.10–3.13 (tested), if a newer base is ever needed for the pip variants.
- **The oracle decides truth, never a scanner.** The VEX status is derived from it, so every VEX statement is correct by construction. The experiment then measures only whether the statement is *applied*.
- **local-backport uses Ubuntu's own patch.** The result is code byte-identical to the patched deb and to 6.0.2, which isolates packaging and identity as the only variables.
- **`fixed` vs `not_affected/vulnerable_code_not_present` for the backport.** Both were issued, and scanners treat them identically. The evidence (a patch, identical to the fixed release) fits CISA's `fixed` better.
- **Pinned tools.** Syft is pinned by digest, Grype and Trivy by tag. Vulnerability DBs are frozen after the first update: `GRYPE_DB_AUTO_UPDATE=false`, `--skip-db-update`. Their dates are in `out/versions.txt`.

## Next steps (suggested order)

1. **Image-scoped VEX.** Push the images to a local registry (`registry:2`) so the SBOM roots get `pkg:oci/…@sha256` PURLs. Then reissue the VEX as product = image, subcomponent = package, and check:
   - does it stop the leakage in results 4 and 5?
   - do Grype and Trivy both honour it on SBOM input?
2. **More consumers and VEX formats.**
   - cve-bin-tool (reads OpenVEX, CSAF and CycloneDX VEX);
   - OWASP Dependency-Track (CycloneDX VEX);
   - Trivy with CSAF and CycloneDX VEX: does the format change what gets applied?
3. **Distro-published VEX.** Canonical's OpenVEX feed (`security-metadata.canonical.com/vex/`) returned 503 on 2026-10-08. If it's available, compare its `python3-yaml` statement with ours.
4. **Runtime SBOM.** A memory-based tool (MEM-SBOM, Volatility 3) records the *import* name `yaml`. Test whether `pkg:pypi/yaml@5.3.1` matches any advisory; an earlier, unverified observation says it doesn't.
5. **Generalise.** Repeat with a second ecosystem (npm or Go) and a second CVE, to see which findings are PyYAML-specific.

## Gotchas

- **Don't run podman containers in parallel on the same `:Z` volume.** SELinux relabelling races, and Trivy fails with `mkdir /root/.cache/trivy/fanal: permission denied`. `run.py` runs them in sequence.
- **Old pip doesn't record the install origin.** Ubuntu 20.04's pip 20.0.2 predates `direct_url.json`, so the venvs upgrade pip to 25.0.1, the last version for Python 3.8. Without that, git and local installs leave no trace of where they came from.
- **Ubuntu 20.04 is in ESM.** Grype logs `using channel "esm"`. The release-pocket package (`5.3.1-1`) is still installable by pinning its version.
- **Expected `dpkg --verify` warning.** It flags `/usr/share/doc/python3-yaml/README`, because the minimal image strips docs. The code files verify.
- **Image tars are about 1 GB** (`out/images/`, git-ignored). `run.py build` recreates them.

## Sources

- CISA: [Minimum Requirements for VEX (2023)](https://www.cisa.gov/sites/default/files/2023-04/minimum-requirements-for-vex-508c.pdf), [VEX Status Justifications (2022)](https://www.cisa.gov/sites/default/files/publications/VEX_Status_Justification_Jun22.pdf), [When to Issue VEX Information (2023)](https://www.cisa.gov/sites/default/files/2023-11/When-to-Issue-a-VEX-508c.pdf), [VEX Use Cases (2022)](https://www.cisa.gov/sites/default/files/2023-01/VEX_Use_Cases_Aprill2022.pdf)
- [OpenVEX spec](https://github.com/openvex/spec), [vexctl](https://github.com/openvex/vexctl), [Trivy VEX docs](https://trivy.dev/docs/v0.53/supply-chain/vex/), [Grype](https://github.com/anchore/grype)
