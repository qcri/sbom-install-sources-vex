"""Draw the blog figures as SVG (standard library only). Render them to PNG with render.sh.

The data is embedded so the script also works outside the experiment repository:
- VERDICTS: out/results.json of the 2026-10-08 run (verdict = does the scan report CVE-2020-14343, vs the oracle);
- REACH: RESULTS.md §4.5 / out/probe/probes.txt (2026-10-13 probes).

usage: python3 -I make_figures.py [output_dir]      (default: svg/ next to this script)
"""
import sys
from pathlib import Path

OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent / "svg"

SANS = "Noto Sans, DejaVu Sans, Helvetica, Arial, sans-serif"
MONO = "DejaVu Sans Mono, Noto Sans Mono, Menlo, monospace"
SURFACE, PLANE, CARD = "#fcfcfb", "#f4f3ef", "#ffffff"
INK, INK2, MUTED, HAIR, AXIS = "#0b0b0b", "#52514e", "#898781", "#e1e0d9", "#c3c2b7"
GOOD, GOOD_WASH, GOOD_TEXT, CRIT = "#0ca30c", "#d8efd7", "#006300", "#d03b3b"
ACCENT = "#2a78d6"

VARIANTS = ["deb-unpatched", "deb-patched", "pypi", "git", "local", "local-backport", "pypi-fixed"]
VULNERABLE = {"deb-unpatched", "pypi", "git", "local"}
PAIRS = [("Syft", "Grype"), ("Syft", "Trivy"), ("Trivy", "Grype"), ("Trivy", "Trivy")]
# ok / FP / FN per SBOM->scanner pair, in PAIRS order
VERDICTS = {
    "Without VEX": {
        "deb-unpatched": ["ok", "ok", "FN", "ok"], "deb-patched": ["FP", "FP", "ok", "ok"],
        "pypi": ["ok"] * 4, "git": ["ok"] * 4, "local": ["ok"] * 4,
        "local-backport": ["FP"] * 4, "pypi-fixed": ["ok"] * 4},
    "With supplier VEX (--vex)": {
        "deb-unpatched": ["ok", "ok", "FN", "ok"], "deb-patched": ["FP", "FP", "ok", "ok"],
        "pypi": ["ok"] * 4, "git": ["ok"] * 4, "local": ["ok"] * 4,
        "local-backport": ["ok"] * 4, "pypi-fixed": ["ok"] * 4},
    "With vexctl filter (SARIF)": {
        "deb-unpatched": ["ok", "ok", "FN", "ok"], "deb-patched": ["FP", "ok†", "ok", "ok"],
        "pypi": ["ok"] * 4, "git": ["ok"] * 4, "local": ["ok"] * 4,
        "local-backport": ["FP", "ok", "FP", "ok"], "pypi-fixed": ["ok"] * 4},
}
# statement -> verdicts on local-backport (Grype, Trivy) and pypi (Grype, Trivy); "-" = not run
REACH = [
    ("Supplier statement", "pkg:pypi/pyyaml@5.3.1%2Bacme1 · CVE + GHSA", ["ok", "ok", "-", "-"]),
    ("(a) no GHSA alias", "pkg:pypi/pyyaml@5.3.1%2Bacme1 · CVE only", ["FP", "ok", "ok", "ok"]),
    ("(b) upstream's version", "pkg:pypi/pyyaml@5.3.1 · CVE + GHSA", ["FP", "FP", "FN", "FN"]),
    ("(c) no version", "pkg:pypi/pyyaml · CVE + GHSA", ["ok", "ok", "FN", "FN"]),
    ("(d) no CVE", "pkg:pypi/pyyaml@5.3.1%2Bacme1 · GHSA only", ["ok", "FP", "-", "-"]),
    ("(e) extra qualifier", "pkg:pypi/pyyaml@5.3.1%2Bacme1?foo=bar", ["FP", "FP", "-", "-"]),
]


def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


class Svg:
    """A tiny SVG builder: shapes and text in user units, light surface, one arrowhead marker."""

    def __init__(self, w, h, title, desc):
        self.w, self.h, self.title, self.desc, self.parts = w, h, title, desc, []

    def rect(self, x, y, w, h, fill=CARD, stroke=AXIS, rx=10, sw=1):
        self.parts.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" fill="{fill}" '
                          f'stroke="{stroke}" stroke-width="{sw}"/>')

    def text(self, x, y, s, size=15, fill=INK, weight=400, anchor="start", family=SANS):
        self.parts.append(f'<text x="{x}" y="{y}" font-family="{family}" font-size="{size}" font-weight="{weight}" '
                          f'fill="{fill}" text-anchor="{anchor}">{esc(s)}</text>')

    def line(self, pts, stroke=INK2, sw=1.6, arrow=True):
        d = "M" + " L".join(f"{x},{y}" for x, y in pts)
        self.parts.append(f'<path d="{d}" fill="none" stroke="{stroke}" stroke-width="{sw}" stroke-linejoin="round" '
                          f'stroke-linecap="round"{" marker-end=" + chr(34) + "url(#arrow)" + chr(34) if arrow else ""}/>')

    def curve(self, x1, y1, x2, y2, stroke=MUTED, sw=1.6):
        mx = (x1 + x2) / 2
        self.parts.append(f'<path d="M{x1},{y1} C{mx},{y1} {mx},{y2} {x2},{y2}" fill="none" stroke="{stroke}" '
                          f'stroke-width="{sw}" stroke-linecap="round"/>')

    def badge(self, cx, cy, n):
        self.parts.append(f'<circle cx="{cx}" cy="{cy}" r="11" fill="{CRIT}" stroke="{SURFACE}" stroke-width="2"/>')
        self.text(cx, cy + 4.5, str(n), 13, "#ffffff", 700, "middle")

    def cell(self, x, y, w, h, v):
        """A verdict cell: pale green wash + check, or critical red + FP/FN, or an empty 'not run' slot."""
        if v == "-":
            self.rect(x, y, w, h, SURFACE, HAIR, 6)
            self.text(x + w / 2, y + h / 2 + 5, "–", 15, MUTED, 400, "middle")
        elif v.startswith("ok"):
            self.rect(x, y, w, h, GOOD_WASH, "none", 6)
            self.text(x + w / 2, y + h / 2 + 6, "✓" + v[2:], 17, GOOD_TEXT, 700, "middle")
        else:
            self.rect(x, y, w, h, CRIT, "none", 6)
            self.text(x + w / 2, y + h / 2 + 5, v, 14, "#ffffff", 700, "middle")

    def save(self, name):
        OUT.mkdir(parents=True, exist_ok=True)
        head = (f'<svg xmlns="http://www.w3.org/2000/svg" width="{self.w}" height="{self.h}" '
                f'viewBox="0 0 {self.w} {self.h}" role="img">\n<title>{esc(self.title)}</title>\n'
                f'<desc>{esc(self.desc)}</desc>\n<defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" '
                f'markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" '
                f'fill="{INK2}"/></marker></defs>\n<rect width="100%" height="100%" fill="{SURFACE}"/>\n')
        (OUT / f"{name}.svg").write_text(head + "\n".join(self.parts) + "\n</svg>\n")
        print("wrote", OUT / f"{name}.svg")


def box(s, x, y, w, h, title, sub, fill=CARD):
    s.rect(x, y, w, h, fill)
    s.text(x + 16, y + 29, title, 16, INK, 600)
    s.text(x + 16, y + 51, sub, 13.5, INK2)


def pipeline():
    s = Svg(1200, 520, "The experiment's pipeline",
            "Supplier side: an image goes to an SBOM generator and to an oracle that drives the VEX statement. "
            "Consumer side: a scanner reads SBOM and VEX, or a post-filter applies the VEX to SARIF; the result "
            "is compared with the oracle. Five numbered badges mark where the findings occur.")
    for x, label, sub in ((16, "SUPPLIER", "builds the image and describes it"),
                          (616, "CONSUMER", "scans the SBOM and applies the VEX")):
        s.rect(x, 16, 568, 430, PLANE, HAIR, 14)
        s.text(x + 22, 44, label, 13, MUTED, 700)
        s.text(x + 22 + 92, 44, sub, 13, MUTED)
    box(s, 40, 74, 220, 70, "Container image", "7 ways to install PyYAML")
    box(s, 330, 74, 230, 70, "SBOM generator", "Syft or Trivy → CycloneDX")
    box(s, 40, 300, 220, 70, "Oracle", "runs the PoC in the image")
    box(s, 330, 300, 230, 70, "VEX statement", "vexctl create, status from oracle")
    box(s, 650, 74, 230, 70, "Scanner", "Grype or Trivy, --vex")
    box(s, 650, 300, 230, 70, "Post-filter", "vexctl filter on SARIF")
    box(s, 950, 190, 216, 70, "Verdict", "✓ · FP · FN vs the oracle")
    s.line([(260, 109), (326, 109)])
    s.line([(150, 144), (150, 296)])
    s.line([(260, 335), (326, 335)])
    s.line([(560, 109), (646, 109)])
    s.text(603, 132, "SBOM", 13, INK2, 600, "middle")
    s.line([(560, 318), (720, 148)])
    s.text(653, 252, "--vex", 13, INK2, 600, "start")
    s.line([(560, 352), (646, 352)])
    s.text(603, 375, "VEX", 13, INK2, 600, "middle")
    s.line([(765, 144), (765, 296)])
    s.text(773, 226, "SARIF", 13, INK2, 600)
    s.line([(880, 109), (946, 205)])
    s.text(905, 145, "findings", 13, INK2, 600, "start")
    s.line([(880, 335), (946, 245)])
    s.line([(150, 370), (150, 412), (1058, 412), (1058, 264)], MUTED, 1.4)
    s.text(604, 404, "ground truth (oracle)", 13, MUTED, 600, "middle")
    for i, (cx, cy) in enumerate(((586, 88), (610, 88), (634, 88), (632, 222), (872, 300)), 1):
        s.badge(cx, cy, i)
    legend = ["duplicate PyPI component", "source-package fields", "install origin",
              "statement matching", "product-blind post-filter"]
    x = 30
    for i, t in enumerate(legend, 1):
        s.badge(x + 11, 482, i)
        s.text(x + 28, 487, t, 14, INK2)
        x += 28 + len(t) * 7.6 + 26
    s.save("sbom-vex-pipeline")


def identities():
    s = Svg(1200, 540, "Seven installs, five identities, two versions of the code",
            "Each install (centre) is linked to the PURLs Syft records for it (left) and to the version of "
            "yaml/constructor.py it contains (right). pkg:pypi/pyyaml@5.3.1 is shared by five installs, "
            "including the patched deb.")
    s.text(24, 40, "Identity in Syft's SBOM (PURL)", 15, INK, 600)
    s.text(610, 40, "Install", 15, INK, 600, "middle")
    s.text(880, 40, "Code installed: yaml/constructor.py", 15, INK, 600)
    left = {"deb1": ("pkg:deb/ubuntu/python3-yaml@5.3.1-1", 70), "deb2": ("pkg:deb/ubuntu/python3-yaml@5.3.1-1ubuntu0.1", 130),
            "pypi": ("pkg:pypi/pyyaml@5.3.1", 222), "acme": ("pkg:pypi/pyyaml@5.3.1%2Bacme1", 370),
            "fixed": ("pkg:pypi/pyyaml@6.0.2", 430)}
    centre = {v: 70 + 60 * i for i, v in enumerate(VARIANTS)}
    links = {"deb-unpatched": ["deb1", "pypi"], "deb-patched": ["deb2", "pypi"], "pypi": ["pypi"], "git": ["pypi"],
             "local": ["pypi"], "local-backport": ["acme"], "pypi-fixed": ["fixed"]}
    code = {"vuln": 190, "fix": 372}
    for v, ys in centre.items():
        for k in links[v]:
            hot = v == "deb-patched" and k == "pypi"
            s.curve(520, ys + 20, 424, left[k][1] + 20, CRIT if hot else MUTED, 2.6 if hot else 1.6)
        s.curve(700, ys + 20, 876, code["vuln" if v in VULNERABLE else "fix"] + 28)
    for k, (purl, y) in left.items():
        s.rect(24, y, 400, 40, CARD, CRIT if k == "pypi" else AXIS, 8, 2 if k == "pypi" else 1)
        s.text(38, y + 25, purl, 13, INK, 400, "start", MONO)
    s.text(24, 284, "shared by 5 installs: 4 vulnerable, 1 patched", 13.5, INK2, 600)
    for v, y in centre.items():
        s.rect(520, y, 180, 40, CARD, AXIS, 8)
        s.text(610, y + 26, v, 15, INK, 600, "middle")
    for k, y, color, title, sub in (("vuln", code["vuln"], CRIT, "vulnerable · sha256 3b751a7f…", "PoC returns (42,)"),
                                    ("fix", code["fix"], GOOD, "patched · sha256 90d8247d…", "PoC: ConstructorError")):
        s.rect(876, y, 300, 56, CARD, AXIS, 8)
        s.rect(876, y, 8, 56, color, "none", 3)
        s.text(898, y + 24, title, 14.5, INK, 600)
        s.text(898, y + 44, sub, 13, INK2)
    s.text(24, 515, "Red link: the patched deb's files also appear under the vulnerable release's PURL.", 13.5, INK2)
    s.save("sbom-vex-identities")


def verdict_grid(s, x0, y0, rows, header, subheads, cw=62, ch=40, gap=4, rh=50):
    """Draw one panel of verdict cells; returns the number of wrong cells."""
    s.text(x0 + (len(subheads) * (cw + gap) - gap) / 2, y0, header, 15, INK, 600, "middle")
    for j, (a, b) in enumerate(subheads):
        cx = x0 + j * (cw + gap) + cw / 2
        s.text(cx, y0 + 30, a, 13.5, INK2, 400, "middle")
        s.text(cx, y0 + 47, "→ " + b, 13.5, INK2, 400, "middle")
    wrong = 0
    for i, cells in enumerate(rows):
        for j, v in enumerate(cells):
            s.cell(x0 + j * (cw + gap), y0 + 62 + i * rh, cw, ch, v)
            wrong += v in ("FP", "FN")
    return wrong


def verdicts():
    s = Svg(1200, 620, "Verdicts for CVE-2020-14343 per install and SBOM→scanner pair",
            "Three panels (without VEX, with --vex, with vexctl filter); rows are the seven installs, columns the "
            "four SBOM generator → scanner pairs. Cells show ✓ when the scan agrees with the oracle, FP or FN otherwise.")
    for i, v in enumerate(VARIANTS):
        y = 132 + i * 50
        s.text(24, y + 17, v, 15, INK, 600)
        s.text(24, y + 36, "vulnerable" if v in VULNERABLE else "not vulnerable", 13.5, INK2)
    for k, (title, grid) in enumerate(VERDICTS.items()):
        x0 = 262 + k * 312
        n = verdict_grid(s, x0, 70, [grid[v] for v in VARIANTS], title, PAIRS)
        s.text(x0 + 130, 518, f"{n} of 28 wrong", 14, INK, 600, "middle")
    y = 572
    s.cell(24, y - 20, 34, 28, "ok")
    s.text(66, y, "agrees with the oracle", 13.5, INK2)
    s.cell(250, y - 20, 34, 28, "FP")
    s.text(292, y, "reported, not vulnerable", 13.5, INK2)
    s.cell(494, y - 20, 34, 28, "FN")
    s.text(536, y, "vulnerable, not reported", 13.5, INK2)
    s.text(742, y, "† right for the wrong reason: vexctl ignores the product", 13.5, INK2)
    s.save("sbom-vex-verdicts")


def duplicate():
    s = Svg(1200, 470, "One deb install becomes two SBOM components",
            "dpkg installs python3-yaml 5.3.1-1ubuntu0.1, which contains the patched constructor.py and an egg-info "
            "saying Version 5.3.1. Syft reports a deb component and a PyPI component. With Syft JSON or SPDX the "
            "ownership relationship survives and Grype drops the PyPI entry; with CycloneDX it is lost and both "
            "scanners report a false positive.")
    s.rect(24, 60, 330, 250, PLANE, HAIR, 12)
    s.text(44, 90, "INSTALLED BY DPKG", 12.5, MUTED, 700)
    s.text(44, 116, "python3-yaml 5.3.1-1ubuntu0.1", 16, INK, 600)
    for y, f, note in ((142, "yaml/constructor.py", "patched (same bytes as 6.0.2)"),
                       (222, "PyYAML-5.3.1.egg-info", "Version: 5.3.1 (upstream's)")):
        s.rect(44, y, 290, 62, CARD, AXIS, 8)
        s.text(60, y + 26, f, 13.5, INK, 600, "start", MONO)
        s.text(60, y + 47, note, 13, INK2)
    s.text(450, 50, "Syft catalogs two components", 15, INK, 600)
    s.rect(430, 72, 360, 66, CARD, AXIS, 8)
    s.text(446, 98, "pkg:deb/ubuntu/python3-yaml@5.3.1-1ubuntu0.1", 12.2, INK, 400, "start", MONO)
    s.text(446, 121, "dpkg cataloger", 13, INK2)
    s.rect(430, 218, 360, 66, CARD, CRIT, 8, 2)
    s.text(446, 244, "pkg:pypi/pyyaml@5.3.1", 13.5, INK, 400, "start", MONO)
    s.text(446, 267, "Python cataloger, from the egg-info", 13, INK2)
    s.line([(354, 105), (426, 105)])
    s.line([(334, 253), (426, 251)])
    s.line([(610, 138), (610, 214)], INK2, 1.6)
    s.text(598, 172, "ownership-by-file-overlap", 13, INK2, 600, "end", MONO)
    s.text(598, 192, "(the deb owns the PyPI entry)", 13, INK2, 400, "end")
    s.rect(850, 60, 326, 120, CARD, AXIS, 10)
    s.text(868, 88, "Syft JSON or SPDX", 15.5, INK, 600)
    s.text(868, 112, "relationship kept → Grype drops", 13.5, INK2)
    s.text(868, 132, "the PyPI entry before matching", 13.5, INK2)
    s.cell(868, 144, 34, 26, "ok")
    s.text(912, 162, "no finding", 13.5, INK, 700)
    s.rect(850, 200, 326, 140, CARD, CRIT, 10, 2)
    s.text(868, 228, "CycloneDX", 15.5, INK, 600)
    s.text(868, 252, "relationship dropped → the PyPI entry", 13.5, INK2)
    s.text(868, 272, "looks like the PyPI release and matches", 13.5, INK2)
    s.text(868, 292, "GHSA-8q59-q68h-6hv4 (< 5.4)", 13.5, INK2, 400, "start", MONO)
    s.cell(868, 304, 34, 26, "FP")
    s.text(912, 322, "Grype and Trivy", 13.5, INK, 700)
    s.line([(796, 105), (812, 105), (812, 251), (796, 251)], AXIS, 1.6, arrow=False)   # both components, one SBOM
    s.line([(812, 178), (846, 122)])
    s.line([(812, 178), (846, 266)])
    s.text(24, 372, "The supplier's VEX names the deb PURL, so it cannot reach the finding on pkg:pypi/pyyaml@5.3.1.",
           14, INK2)
    s.text(24, 398, "Trivy as a scanner does not use the relationship: it reports the false positive from Syft's SPDX too.",
           14, INK2)
    s.text(24, 424, "Trivy as an SBOM generator never lists the PyPI entry: it skips Python packages that dpkg owns.",
           14, INK2)
    s.save("sbom-vex-duplicate")


def reach():
    s = Svg(940, 580, "How far a VEX statement reaches",
            "Rows are copies of the supplier's local-backport statement with one field changed; columns are the "
            "verdict after applying it to the local-backport image (not vulnerable) and the pypi image (vulnerable), "
            "for Grype and Trivy.")
    cw, ch, gap, rh, x0, sep = 96, 40, 4, 56, 450, 36
    groups = (("local-backport", "not vulnerable"), ("pypi", "vulnerable"))
    for g, (name, truth) in enumerate(groups):
        gx = x0 + g * (2 * (cw + gap) + sep)
        s.text(gx + cw + gap / 2, 44, name, 15, INK, 600, "middle")
        s.text(gx + cw + gap / 2, 64, truth, 13, INK2, 400, "middle")
        for j, sc in enumerate(("Grype", "Trivy")):
            s.text(gx + j * (cw + gap) + cw / 2, 92, sc, 13, INK2, 400, "middle")
    for i, (label, product, cells) in enumerate(REACH):
        y = 110 + i * rh
        s.text(24, y + 17, label, 15, INK, 600)
        s.text(24, y + 38, product, 13.5, INK2, 400, "start", MONO)
        for j, v in enumerate(cells):
            g, k = divmod(j, 2)
            s.cell(x0 + g * (2 * (cw + gap) + sep) + k * (cw + gap), y, cw, ch, v)
    y = 476
    s.cell(24, y - 20, 34, 28, "ok")
    s.text(66, y, "agrees with the oracle", 13.5, INK2)
    s.cell(330, y - 20, 34, 28, "FN")
    s.text(372, y, "statement leaked: a real finding hidden", 13.5, INK2)
    s.cell(24, y + 16, 34, 28, "FP")
    s.text(66, y + 36, "statement not applied: the backport stays flagged", 13.5, INK2)
    s.text(24, y + 80, "– not run. Syft SBOMs; status fixed in every statement.", 14, MUTED)
    s.save("sbom-vex-reach")


if __name__ == "__main__":
    pipeline()
    identities()
    verdicts()
    duplicate()
    reach()
