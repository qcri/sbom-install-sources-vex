## PyYAML identity recorded by each SBOM generator

| variant | SBOM generator | PyYAML PURL(s) | deb source package recorded in | install origin recorded outside name@version |
|---|---|---|---|---|
| deb-unpatched | syft | `pkg:deb/ubuntu/python3-yaml@5.3.1-1?arch=amd64&distro=ubuntu-20.04&upstream=pyyaml`<br>`pkg:pypi/pyyaml@5.3.1` | purl `upstream=pyyaml`<br>`syft:metadata:source=pyyaml` | — |
| deb-unpatched | trivy | `pkg:deb/ubuntu/python3-yaml@5.3.1-1?arch=amd64&distro=ubuntu-20.04` | `aquasecurity:trivy:SrcName=pyyaml` | — |
| deb-patched | syft | `pkg:deb/ubuntu/python3-yaml@5.3.1-1ubuntu0.1?arch=amd64&distro=ubuntu-20.04&upstream=pyyaml`<br>`pkg:pypi/pyyaml@5.3.1` | purl `upstream=pyyaml`<br>`syft:metadata:source=pyyaml` | — |
| deb-patched | trivy | `pkg:deb/ubuntu/python3-yaml@5.3.1-1ubuntu0.1?arch=amd64&distro=ubuntu-20.04` | `aquasecurity:trivy:SrcName=pyyaml` | — |
| pypi | syft | `pkg:pypi/pyyaml@5.3.1` | — | — |
| pypi | trivy | `pkg:pypi/pyyaml@5.3.1` | — | — |
| git | syft | `pkg:pypi/pyyaml@5.3.1?vcs_url=git%2Bhttps%3A%2F%2Fgithub.com%2Fyaml%2Fpyyaml.git%40538b5c93f7d5dee40322893c1e524e94a4f8bbde` | — | purl `vcs_url`<br>vcs reference `https://github.com/yaml/pyyaml.git` (commit: 538b5c93f7d5dee40322893c1e524e94a4f8bbde) |
| git | trivy | `pkg:pypi/pyyaml@5.3.1` | — | — |
| local | syft | `pkg:pypi/pyyaml@5.3.1` | — | vcs reference `file:///src/pyyaml` |
| local | trivy | `pkg:pypi/pyyaml@5.3.1` | — | — |
| local-backport | syft | `pkg:pypi/pyyaml@5.3.1%2Bacme1` | — | vcs reference `file:///src/pyyaml` |
| local-backport | trivy | `pkg:pypi/pyyaml@5.3.1%2Bacme1` | — | — |
| local-relabel | syft | `pkg:pypi/pyyaml@6.0.2` | — | vcs reference `file:///src/pyyaml` |
| local-relabel | trivy | `pkg:pypi/pyyaml@6.0.2` | — | — |
| pypi-fixed | syft | `pkg:pypi/pyyaml@6.0.2` | — | — |
| pypi-fixed | trivy | `pkg:pypi/pyyaml@6.0.2` | — | — |

## Verdicts for CVE-2020-14343 / GHSA-8q59-q68h-6hv4

A verdict compares a scan with the oracle: ✅ agrees, ❌ FP reported but not vulnerable, ❌ FN vulnerable but not reported. `vexctl filter` applies the same VEX document to the SARIF output of the scan without VEX.

| variant | oracle | SBOM→scanner | VEX doc | findings without VEX | verdict | findings with `--vex` | suppressed as | verdict | `vexctl filter` (SARIF) | verdict |
|---|---|---|---|---|---|---|---|---|---|---|
| deb-unpatched | vulnerable | syft→grype | vex | `CVE-2020-14343` on `pkg:deb/ubuntu/python3-yaml@5.3.1-1?arch=amd64&distro=ubuntu-20.04&upstream=pyyaml`<br>`GHSA-8q59-q68h-6hv4` on `pkg:pypi/pyyaml@5.3.1` | ✅ | `CVE-2020-14343` on `pkg:deb/ubuntu/python3-yaml@5.3.1-1?arch=amd64&distro=ubuntu-20.04&upstream=pyyaml`<br>`GHSA-8q59-q68h-6hv4` on `pkg:pypi/pyyaml@5.3.1` | — | ✅ | 2 left | ✅ |
| deb-unpatched | vulnerable | syft→trivy | vex | `CVE-2020-14343` on `pkg:pypi/pyyaml@5.3.1` | ✅ | `CVE-2020-14343` on `pkg:pypi/pyyaml@5.3.1` | — | ✅ | 1 left | ✅ |
| deb-unpatched | vulnerable | trivy→grype | vex | — | ❌ FN | — | — | ❌ FN | 0 left | ❌ FN |
| deb-unpatched | vulnerable | trivy→trivy | vex | `CVE-2020-14343` on `pkg:deb/ubuntu/python3-yaml@5.3.1-1?arch=amd64&distro=ubuntu-20.04` | ✅ | `CVE-2020-14343` on `pkg:deb/ubuntu/python3-yaml@5.3.1-1?arch=amd64&distro=ubuntu-20.04` | — | ✅ | 1 left | ✅ |
| deb-patched | not vulnerable | syft→grype | vex | `GHSA-8q59-q68h-6hv4` on `pkg:pypi/pyyaml@5.3.1` | ❌ FP | `GHSA-8q59-q68h-6hv4` on `pkg:pypi/pyyaml@5.3.1` | — | ❌ FP | 1 left | ❌ FP |
| deb-patched | not vulnerable | syft→trivy | vex | `CVE-2020-14343` on `pkg:pypi/pyyaml@5.3.1` | ❌ FP | `CVE-2020-14343` on `pkg:pypi/pyyaml@5.3.1` | — | ❌ FP | 0 left | ✅ |
| deb-patched | not vulnerable | trivy→grype | vex | — | ✅ | — | — | ✅ | 0 left | ✅ |
| deb-patched | not vulnerable | trivy→trivy | vex | — | ✅ | — | — | ✅ | 0 left | ✅ |
| pypi | vulnerable | syft→grype | vex | `GHSA-8q59-q68h-6hv4` on `pkg:pypi/pyyaml@5.3.1` | ✅ | `GHSA-8q59-q68h-6hv4` on `pkg:pypi/pyyaml@5.3.1` | — | ✅ | 1 left | ✅ |
| pypi | vulnerable | syft→trivy | vex | `CVE-2020-14343` on `pkg:pypi/pyyaml@5.3.1` | ✅ | `CVE-2020-14343` on `pkg:pypi/pyyaml@5.3.1` | — | ✅ | 1 left | ✅ |
| pypi | vulnerable | trivy→grype | vex | `GHSA-8q59-q68h-6hv4` on `pkg:pypi/pyyaml@5.3.1` | ✅ | `GHSA-8q59-q68h-6hv4` on `pkg:pypi/pyyaml@5.3.1` | — | ✅ | 1 left | ✅ |
| pypi | vulnerable | trivy→trivy | vex | `CVE-2020-14343` on `pkg:pypi/pyyaml@5.3.1` | ✅ | `CVE-2020-14343` on `pkg:pypi/pyyaml@5.3.1` | — | ✅ | 1 left | ✅ |
| git | vulnerable | syft→grype | vex | `GHSA-8q59-q68h-6hv4` on `pkg:pypi/pyyaml@5.3.1?vcs_url=git%2Bhttps%3A%2F%2Fgithub.com%2Fyaml%2Fpyyaml.git%40538b5c93f7d5dee40322893c1e524e94a4f8bbde` | ✅ | `GHSA-8q59-q68h-6hv4` on `pkg:pypi/pyyaml@5.3.1?vcs_url=git%2Bhttps%3A%2F%2Fgithub.com%2Fyaml%2Fpyyaml.git%40538b5c93f7d5dee40322893c1e524e94a4f8bbde` | — | ✅ | 1 left | ✅ |
| git | vulnerable | syft→trivy | vex | `CVE-2020-14343` on `pkg:pypi/pyyaml@5.3.1?vcs_url=git%2Bhttps:%2F%2Fgithub.com%2Fyaml%2Fpyyaml.git%40538b5c93f7d5dee40322893c1e524e94a4f8bbde` | ✅ | `CVE-2020-14343` on `pkg:pypi/pyyaml@5.3.1?vcs_url=git%2Bhttps:%2F%2Fgithub.com%2Fyaml%2Fpyyaml.git%40538b5c93f7d5dee40322893c1e524e94a4f8bbde` | — | ✅ | 1 left | ✅ |
| git | vulnerable | trivy→grype | vex | `GHSA-8q59-q68h-6hv4` on `pkg:pypi/pyyaml@5.3.1` | ✅ | `GHSA-8q59-q68h-6hv4` on `pkg:pypi/pyyaml@5.3.1` | — | ✅ | 1 left | ✅ |
| git | vulnerable | trivy→trivy | vex | `CVE-2020-14343` on `pkg:pypi/pyyaml@5.3.1` | ✅ | `CVE-2020-14343` on `pkg:pypi/pyyaml@5.3.1` | — | ✅ | 1 left | ✅ |
| local | vulnerable | syft→grype | vex | `GHSA-8q59-q68h-6hv4` on `pkg:pypi/pyyaml@5.3.1` | ✅ | `GHSA-8q59-q68h-6hv4` on `pkg:pypi/pyyaml@5.3.1` | — | ✅ | 1 left | ✅ |
| local | vulnerable | syft→trivy | vex | `CVE-2020-14343` on `pkg:pypi/pyyaml@5.3.1` | ✅ | `CVE-2020-14343` on `pkg:pypi/pyyaml@5.3.1` | — | ✅ | 1 left | ✅ |
| local | vulnerable | trivy→grype | vex | `GHSA-8q59-q68h-6hv4` on `pkg:pypi/pyyaml@5.3.1` | ✅ | `GHSA-8q59-q68h-6hv4` on `pkg:pypi/pyyaml@5.3.1` | — | ✅ | 1 left | ✅ |
| local | vulnerable | trivy→trivy | vex | `CVE-2020-14343` on `pkg:pypi/pyyaml@5.3.1` | ✅ | `CVE-2020-14343` on `pkg:pypi/pyyaml@5.3.1` | — | ✅ | 1 left | ✅ |
| local-backport | not vulnerable | syft→grype | vex | `GHSA-8q59-q68h-6hv4` on `pkg:pypi/pyyaml@5.3.1%2Bacme1` | ❌ FP | — | fixed | ✅ | 1 left | ❌ FP |
| local-backport | not vulnerable | syft→grype | vex-vcnp | `GHSA-8q59-q68h-6hv4` on `pkg:pypi/pyyaml@5.3.1%2Bacme1` | ❌ FP | — | not_affected | ✅ | 1 left | ❌ FP |
| local-backport | not vulnerable | syft→trivy | vex | `CVE-2020-14343` on `pkg:pypi/pyyaml@5.3.1%2Bacme1` | ❌ FP | — | fixed | ✅ | 0 left | ✅ |
| local-backport | not vulnerable | syft→trivy | vex-vcnp | `CVE-2020-14343` on `pkg:pypi/pyyaml@5.3.1%2Bacme1` | ❌ FP | — | not_affected | ✅ | 0 left | ✅ |
| local-backport | not vulnerable | trivy→grype | vex | `GHSA-8q59-q68h-6hv4` on `pkg:pypi/pyyaml@5.3.1%2Bacme1` | ❌ FP | — | fixed | ✅ | 1 left | ❌ FP |
| local-backport | not vulnerable | trivy→grype | vex-vcnp | `GHSA-8q59-q68h-6hv4` on `pkg:pypi/pyyaml@5.3.1%2Bacme1` | ❌ FP | — | not_affected | ✅ | 1 left | ❌ FP |
| local-backport | not vulnerable | trivy→trivy | vex | `CVE-2020-14343` on `pkg:pypi/pyyaml@5.3.1%2Bacme1` | ❌ FP | — | fixed | ✅ | 0 left | ✅ |
| local-backport | not vulnerable | trivy→trivy | vex-vcnp | `CVE-2020-14343` on `pkg:pypi/pyyaml@5.3.1%2Bacme1` | ❌ FP | — | not_affected | ✅ | 0 left | ✅ |
| local-relabel | vulnerable | syft→grype | vex | — | ❌ FN | — | — | ❌ FN | 0 left | ❌ FN |
| local-relabel | vulnerable | syft→trivy | vex | — | ❌ FN | — | — | ❌ FN | 0 left | ❌ FN |
| local-relabel | vulnerable | trivy→grype | vex | — | ❌ FN | — | — | ❌ FN | 0 left | ❌ FN |
| local-relabel | vulnerable | trivy→trivy | vex | — | ❌ FN | — | — | ❌ FN | 0 left | ❌ FN |
| pypi-fixed | not vulnerable | syft→grype | vex | — | ✅ | — | — | ✅ | 0 left | ✅ |
| pypi-fixed | not vulnerable | syft→trivy | vex | — | ✅ | — | — | ✅ | 0 left | ✅ |
| pypi-fixed | not vulnerable | trivy→grype | vex | — | ✅ | — | — | ✅ | 0 left | ✅ |
| pypi-fixed | not vulnerable | trivy→trivy | vex | — | ✅ | — | — | ✅ | 0 left | ✅ |

Wrong verdicts over the 32 SBOM→scanner pairs (each variant's `vex` document): without VEX 11 of 32, with `--vex` 7 of 32, with `vexctl filter` 8 of 32.
