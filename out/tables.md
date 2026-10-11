## PyYAML identity recorded by each SBOM tool

| variant | SBOM tool | PyYAML PURL(s) |
|---|---|---|
| deb-unpatched | syft | `pkg:deb/ubuntu/python3-yaml@5.3.1-1?arch=amd64&distro=ubuntu-20.04&upstream=pyyaml`<br>`pkg:pypi/pyyaml@5.3.1` |
| deb-unpatched | trivy | `pkg:deb/ubuntu/python3-yaml@5.3.1-1?arch=amd64&distro=ubuntu-20.04` |
| deb-patched | syft | `pkg:deb/ubuntu/python3-yaml@5.3.1-1ubuntu0.1?arch=amd64&distro=ubuntu-20.04&upstream=pyyaml`<br>`pkg:pypi/pyyaml@5.3.1` |
| deb-patched | trivy | `pkg:deb/ubuntu/python3-yaml@5.3.1-1ubuntu0.1?arch=amd64&distro=ubuntu-20.04` |
| pypi | syft | `pkg:pypi/pyyaml@5.3.1` |
| pypi | trivy | `pkg:pypi/pyyaml@5.3.1` |
| git | syft | `pkg:pypi/pyyaml@5.3.1?vcs_url=git%2Bhttps%3A%2F%2Fgithub.com%2Fyaml%2Fpyyaml.git%40538b5c93f7d5dee40322893c1e524e94a4f8bbde` |
| git | trivy | `pkg:pypi/pyyaml@5.3.1` |
| local | syft | `pkg:pypi/pyyaml@5.3.1` |
| local | trivy | `pkg:pypi/pyyaml@5.3.1` |
| local-backport | syft | `pkg:pypi/pyyaml@5.3.1%2Bacme1` |
| local-backport | trivy | `pkg:pypi/pyyaml@5.3.1%2Bacme1` |
| pypi-fixed | syft | `pkg:pypi/pyyaml@6.0.2` |
| pypi-fixed | trivy | `pkg:pypi/pyyaml@6.0.2` |

## Findings for CVE-2020-14343 / GHSA-8q59-q68h-6hv4

| variant | oracle | SBOM | scanner | VEX doc | without VEX | with `--vex` | suppressed as | vexctl filter (SARIF) | final vs oracle |
|---|---|---|---|---|---|---|---|---|---|
| deb-unpatched | vulnerable | syft | grype | vex | `CVE-2020-14343` on `pkg:deb/ubuntu/python3-yaml@5.3.1-1?arch=amd64&distro=ubuntu-20.04&upstream=pyyaml`<br>`GHSA-8q59-q68h-6hv4` on `pkg:pypi/pyyaml@5.3.1` | `CVE-2020-14343` on `pkg:deb/ubuntu/python3-yaml@5.3.1-1?arch=amd64&distro=ubuntu-20.04&upstream=pyyaml`<br>`GHSA-8q59-q68h-6hv4` on `pkg:pypi/pyyaml@5.3.1` | — | 2 left | ✅ |
| deb-unpatched | vulnerable | syft | trivy | vex | `CVE-2020-14343` on `pkg:pypi/pyyaml@5.3.1` | `CVE-2020-14343` on `pkg:pypi/pyyaml@5.3.1` | — | 1 left | ✅ |
| deb-unpatched | vulnerable | trivy | grype | vex | — | — | — | 0 left | ❌ FN |
| deb-unpatched | vulnerable | trivy | trivy | vex | `CVE-2020-14343` on `pkg:deb/ubuntu/python3-yaml@5.3.1-1?arch=amd64&distro=ubuntu-20.04` | `CVE-2020-14343` on `pkg:deb/ubuntu/python3-yaml@5.3.1-1?arch=amd64&distro=ubuntu-20.04` | — | 1 left | ✅ |
| deb-patched | not vulnerable | syft | grype | vex | `GHSA-8q59-q68h-6hv4` on `pkg:pypi/pyyaml@5.3.1` | `GHSA-8q59-q68h-6hv4` on `pkg:pypi/pyyaml@5.3.1` | — | 1 left | ❌ FP |
| deb-patched | not vulnerable | syft | trivy | vex | `CVE-2020-14343` on `pkg:pypi/pyyaml@5.3.1` | `CVE-2020-14343` on `pkg:pypi/pyyaml@5.3.1` | — | 0 left | ❌ FP |
| deb-patched | not vulnerable | trivy | grype | vex | — | — | — | 0 left | ✅ |
| deb-patched | not vulnerable | trivy | trivy | vex | — | — | — | 0 left | ✅ |
| pypi | vulnerable | syft | grype | vex | `GHSA-8q59-q68h-6hv4` on `pkg:pypi/pyyaml@5.3.1` | `GHSA-8q59-q68h-6hv4` on `pkg:pypi/pyyaml@5.3.1` | — | 1 left | ✅ |
| pypi | vulnerable | syft | trivy | vex | `CVE-2020-14343` on `pkg:pypi/pyyaml@5.3.1` | `CVE-2020-14343` on `pkg:pypi/pyyaml@5.3.1` | — | 1 left | ✅ |
| pypi | vulnerable | trivy | grype | vex | `GHSA-8q59-q68h-6hv4` on `pkg:pypi/pyyaml@5.3.1` | `GHSA-8q59-q68h-6hv4` on `pkg:pypi/pyyaml@5.3.1` | — | 1 left | ✅ |
| pypi | vulnerable | trivy | trivy | vex | `CVE-2020-14343` on `pkg:pypi/pyyaml@5.3.1` | `CVE-2020-14343` on `pkg:pypi/pyyaml@5.3.1` | — | 1 left | ✅ |
| git | vulnerable | syft | grype | vex | `GHSA-8q59-q68h-6hv4` on `pkg:pypi/pyyaml@5.3.1?vcs_url=git%2Bhttps%3A%2F%2Fgithub.com%2Fyaml%2Fpyyaml.git%40538b5c93f7d5dee40322893c1e524e94a4f8bbde` | `GHSA-8q59-q68h-6hv4` on `pkg:pypi/pyyaml@5.3.1?vcs_url=git%2Bhttps%3A%2F%2Fgithub.com%2Fyaml%2Fpyyaml.git%40538b5c93f7d5dee40322893c1e524e94a4f8bbde` | — | 1 left | ✅ |
| git | vulnerable | syft | trivy | vex | `CVE-2020-14343` on `pkg:pypi/pyyaml@5.3.1?vcs_url=git%2Bhttps:%2F%2Fgithub.com%2Fyaml%2Fpyyaml.git%40538b5c93f7d5dee40322893c1e524e94a4f8bbde` | `CVE-2020-14343` on `pkg:pypi/pyyaml@5.3.1?vcs_url=git%2Bhttps:%2F%2Fgithub.com%2Fyaml%2Fpyyaml.git%40538b5c93f7d5dee40322893c1e524e94a4f8bbde` | — | 1 left | ✅ |
| git | vulnerable | trivy | grype | vex | `GHSA-8q59-q68h-6hv4` on `pkg:pypi/pyyaml@5.3.1` | `GHSA-8q59-q68h-6hv4` on `pkg:pypi/pyyaml@5.3.1` | — | 1 left | ✅ |
| git | vulnerable | trivy | trivy | vex | `CVE-2020-14343` on `pkg:pypi/pyyaml@5.3.1` | `CVE-2020-14343` on `pkg:pypi/pyyaml@5.3.1` | — | 1 left | ✅ |
| local | vulnerable | syft | grype | vex | `GHSA-8q59-q68h-6hv4` on `pkg:pypi/pyyaml@5.3.1` | `GHSA-8q59-q68h-6hv4` on `pkg:pypi/pyyaml@5.3.1` | — | 1 left | ✅ |
| local | vulnerable | syft | trivy | vex | `CVE-2020-14343` on `pkg:pypi/pyyaml@5.3.1` | `CVE-2020-14343` on `pkg:pypi/pyyaml@5.3.1` | — | 1 left | ✅ |
| local | vulnerable | trivy | grype | vex | `GHSA-8q59-q68h-6hv4` on `pkg:pypi/pyyaml@5.3.1` | `GHSA-8q59-q68h-6hv4` on `pkg:pypi/pyyaml@5.3.1` | — | 1 left | ✅ |
| local | vulnerable | trivy | trivy | vex | `CVE-2020-14343` on `pkg:pypi/pyyaml@5.3.1` | `CVE-2020-14343` on `pkg:pypi/pyyaml@5.3.1` | — | 1 left | ✅ |
| local-backport | not vulnerable | syft | grype | vex | `GHSA-8q59-q68h-6hv4` on `pkg:pypi/pyyaml@5.3.1%2Bacme1` | — | fixed | 1 left | ✅ |
| local-backport | not vulnerable | syft | grype | vex-vcnp | `GHSA-8q59-q68h-6hv4` on `pkg:pypi/pyyaml@5.3.1%2Bacme1` | — | not_affected | 1 left | ✅ |
| local-backport | not vulnerable | syft | trivy | vex | `CVE-2020-14343` on `pkg:pypi/pyyaml@5.3.1%2Bacme1` | — | fixed | 0 left | ✅ |
| local-backport | not vulnerable | syft | trivy | vex-vcnp | `CVE-2020-14343` on `pkg:pypi/pyyaml@5.3.1%2Bacme1` | — | not_affected | 0 left | ✅ |
| local-backport | not vulnerable | trivy | grype | vex | `GHSA-8q59-q68h-6hv4` on `pkg:pypi/pyyaml@5.3.1%2Bacme1` | — | fixed | 1 left | ✅ |
| local-backport | not vulnerable | trivy | grype | vex-vcnp | `GHSA-8q59-q68h-6hv4` on `pkg:pypi/pyyaml@5.3.1%2Bacme1` | — | not_affected | 1 left | ✅ |
| local-backport | not vulnerable | trivy | trivy | vex | `CVE-2020-14343` on `pkg:pypi/pyyaml@5.3.1%2Bacme1` | — | fixed | 0 left | ✅ |
| local-backport | not vulnerable | trivy | trivy | vex-vcnp | `CVE-2020-14343` on `pkg:pypi/pyyaml@5.3.1%2Bacme1` | — | not_affected | 0 left | ✅ |
| pypi-fixed | not vulnerable | syft | grype | vex | — | — | — | 0 left | ✅ |
| pypi-fixed | not vulnerable | syft | trivy | vex | — | — | — | 0 left | ✅ |
| pypi-fixed | not vulnerable | trivy | grype | vex | — | — | — | 0 left | ✅ |
| pypi-fixed | not vulnerable | trivy | trivy | vex | — | — | — | 0 left | ✅ |
