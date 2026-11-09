"""Draw the article's three figures as SVG (standard library only), sized for a blog column about 700 px wide.

The data is embedded so the script also works outside the experiment repository:
VERDICTS comes from out/results.json (commit 8986db0; verdict = does the scan report CVE-2020-14343, vs the oracle).

usage: python3 -I make_figures.py [output_dir]      (default: svg/ next to this script)
PNGs in ../: rsvg-convert --zoom 2 --background-color "#fcfcfb" -o <name>.png <name>.svg
"""
import sys
from pathlib import Path

OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent / "svg"
W = 760   # canvas width in user units; rendered at 2x, shown at about 700 px

SANS = "Noto Sans, DejaVu Sans, Helvetica, Arial, sans-serif"
MONO = "DejaVu Sans Mono, Noto Sans Mono, Menlo, monospace"
SURFACE, PLANE, CARD = "#fcfcfb", "#f4f3ef", "#ffffff"
INK, INK2, MUTED, HAIR, AXIS = "#0b0b0b", "#52514e", "#898781", "#e1e0d9", "#c3c2b7"
GOOD, GOOD_WASH, GOOD_TEXT, CRIT = "#0ca30c", "#d8efd7", "#006300", "#d03b3b"

VARIANTS = ["deb-unpatched", "deb-patched", "pypi", "git", "local", "local-backport", "local-relabel", "pypi-fixed"]
VULNERABLE = {"deb-unpatched", "pypi", "git", "local", "local-relabel"}
PAIRS = [("Syft", "Grype"), ("Syft", "Trivy"), ("Trivy", "Grype"), ("Trivy", "Trivy")]
# ok / FP / FN per SBOM generator -> vulnerability scanner pair, in PAIRS order
VERDICTS = {
    "Without VEX": {
        "deb-unpatched": ["ok", "ok", "FN", "ok"], "deb-patched": ["FP", "FP", "ok", "ok"],
        "pypi": ["ok"] * 4, "git": ["ok"] * 4, "local": ["ok"] * 4,
        "local-backport": ["FP"] * 4, "local-relabel": ["FN"] * 4, "pypi-fixed": ["ok"] * 4},
    "With --vex": {
        "deb-unpatched": ["ok", "ok", "FN", "ok"], "deb-patched": ["FP", "FP", "ok", "ok"],
        "pypi": ["ok"] * 4, "git": ["ok"] * 4, "local": ["ok"] * 4,
        "local-backport": ["ok"] * 4, "local-relabel": ["FN"] * 4, "pypi-fixed": ["ok"] * 4},
    "With vexctl filter": {
        "deb-unpatched": ["ok", "ok", "FN", "ok"], "deb-patched": ["FP", "ok†", "ok", "ok"],
        "pypi": ["ok"] * 4, "git": ["ok"] * 4, "local": ["ok"] * 4,
        "local-backport": ["FP", "ok", "FP", "ok"], "local-relabel": ["FN"] * 4, "pypi-fixed": ["ok"] * 4},
}


def esc(s):
    """Escape text for SVG."""
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


class Svg:
    """A tiny SVG builder: shapes and text in user units on a light surface, with one arrowhead marker."""

    def __init__(self, h, title, desc):
        """Start a W-wide canvas of height h with an accessible title and description."""
        self.h, self.title, self.desc, self.parts = h, title, desc, []

    def rect(self, x, y, w, h, fill=CARD, stroke=AXIS, rx=8, sw=1):
        """Add a rounded rectangle."""
        self.parts.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" fill="{fill}" '
                          f'stroke="{stroke}" stroke-width="{sw}"/>')

    def text(self, x, y, s, size=13, fill=INK, weight=400, anchor="start", family=SANS):
        """Add one line of text."""
        self.parts.append(f'<text x="{x}" y="{y}" font-family="{family}" font-size="{size}" font-weight="{weight}" '
                          f'fill="{fill}" text-anchor="{anchor}">{esc(s)}</text>')

    def line(self, pts, stroke=INK2, sw=1.4, arrow=True):
        """Add a polyline, with an arrowhead at the end unless arrow is False."""
        d = "M" + " L".join(f"{x},{y}" for x, y in pts)
        end = ' marker-end="url(#arrow)"' if arrow else ""
        self.parts.append(f'<path d="{d}" fill="none" stroke="{stroke}" stroke-width="{sw}" stroke-linejoin="round" '
                          f'stroke-linecap="round"{end}/>')

    def curve(self, x1, y1, x2, y2, stroke=MUTED, sw=1.4):
        """Add a horizontal S-curve from (x1, y1) to (x2, y2)."""
        mx = (x1 + x2) / 2
        self.parts.append(f'<path d="M{x1},{y1} C{mx},{y1} {mx},{y2} {x2},{y2}" fill="none" stroke="{stroke}" '
                          f'stroke-width="{sw}" stroke-linecap="round"/>')

    def cell(self, x, y, w, h, v):
        """Add a verdict cell: a green wash with a check, or red with FP or FN."""
        if v.startswith("ok"):
            self.rect(x, y, w, h, GOOD_WASH, "none", 5)
            self.text(x + w / 2, y + h / 2 + 5.5, "✓" + v[2:], 15, GOOD_TEXT, 700, "middle")
        else:
            self.rect(x, y, w, h, CRIT, "none", 5)
            self.text(x + w / 2, y + h / 2 + 4.5, v, 12, "#ffffff", 700, "middle")

    def save(self, name):
        """Write the SVG to OUT/<name>.svg."""
        OUT.mkdir(parents=True, exist_ok=True)
        head = (f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{self.h}" '
                f'viewBox="0 0 {W} {self.h}" role="img">\n<title>{esc(self.title)}</title>\n'
                f'<desc>{esc(self.desc)}</desc>\n<defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" '
                f'markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" '
                f'fill="{INK2}"/></marker></defs>\n<rect width="100%" height="100%" fill="{SURFACE}"/>\n')
        (OUT / f"{name}.svg").write_text(head + "\n".join(self.parts) + "\n</svg>\n")
        print("wrote", OUT / f"{name}.svg")


def box(s, x, y, w, title, subs, h=66):
    """Add a card with a bold title and one or two lines of detail."""
    s.rect(x, y, w, h)
    s.text(x + 12, y + 24, title, 13.5, INK, 600)
    for i, sub in enumerate(subs):
        s.text(x + 12, y + 43 + 15 * i, sub, 12, INK2)


def pipeline():
    """Figure 1: supplier and consumer sides of the pipeline, and where the oracle enters."""
    s = Svg(324, "The experiment's pipeline",
            "Supplier side: each image goes to an SBOM generator and to the oracle, whose result sets the status of the "
            "VEX statement. Consumer side: Grype or Trivy scans the SBOM and applies the VEX statement with --vex, or "
            "vexctl filter applies it to their SARIF report; each verdict is compared with the oracle.")
    for x, label, sub in ((8, "SUPPLIER", "builds the image and describes it"),
                          (386, "CONSUMER", "scans the SBOM and applies VEX")):
        s.rect(x, 8, 366, 308, PLANE, HAIR, 12)
        s.text(x + 14, 32, label, 11.5, MUTED, 700)
        s.text(x + 88, 32, sub, 11.5, MUTED)
    box(s, 22, 52, 150, "Container image", ["8 PyYAML installs"])
    box(s, 216, 52, 150, "SBOM generator", ["Syft or Trivy,", "writes CycloneDX"])
    box(s, 22, 210, 150, "Oracle", ["runs the exploit", "in the image"])
    box(s, 216, 210, 150, "VEX statement", ["written by", "vexctl create"])
    box(s, 400, 52, 194, "Vulnerability scanner", ["Grype or Trivy,", "with or without --vex"])
    box(s, 400, 210, 194, "vexctl filter", ["after the scan,", "on the SARIF report"])
    box(s, 622, 131, 120, "Verdict", ["✓, FP or FN", "vs the oracle"])
    s.line([(172, 85), (212, 85)])
    s.line([(97, 118), (97, 206)])
    s.line([(172, 243), (212, 243)])
    s.text(194, 236, "status", 11.5, INK2, 600, "middle")
    s.line([(366, 85), (396, 85)])
    s.text(381, 102, "SBOM", 11.5, INK2, 600, "middle")
    s.line([(366, 226), (440, 122)])
    s.text(420, 176, "--vex", 11.5, INK2, 600)
    s.line([(366, 254), (396, 254)])
    s.text(381, 271, "VEX", 11.5, INK2, 600, "middle")
    s.line([(497, 118), (497, 206)])
    s.text(505, 166, "SARIF", 11.5, INK2, 600)
    s.line([(594, 85), (640, 128)])
    s.text(603, 79, "findings", 11.5, INK2, 600)
    s.line([(594, 243), (640, 200)])
    s.line([(97, 276), (97, 298), (682, 298), (682, 201)], MUTED, 1.3)
    s.text(390, 292, "ground truth from the oracle", 11.5, MUTED, 600, "middle")
    s.save("sbom-vex-pipeline")


def identities():
    """Figure 3: each image linked to the PURLs in its Syft SBOM and to the code in the image (constructor.py)."""
    s = Svg(452, "Eight images, five PURLs, two constructor.py files",
            "Each image (centre) is linked to the PURLs Syft records for it (left) and to the yaml/constructor.py "
            "file in the image (right). pkg:pypi/pyyaml@5.3.1 is shared by five images, including the fixed deb-patched; "
            "pkg:pypi/pyyaml@6.0.2 by the fixed pypi-fixed and the vulnerable local-relabel.")
    lx, lw, cx, cw, rx, rw = 16, 320, 400, 132, 594, 150
    s.text(lx, 32, "PURL in Syft's SBOM", 13.5, INK, 600)
    s.text(cx + cw / 2, 32, "Image", 13.5, INK, 600, "middle")
    s.text(rx, 32, "Code in the image", 13.5, INK, 600)
    row = {v: 52 + 44 * i for i, v in enumerate(VARIANTS)}
    left = {"deb1": ("pkg:deb/ubuntu/python3-yaml@5.3.1-1", row["deb-unpatched"]),
            "deb2": ("pkg:deb/ubuntu/python3-yaml@5.3.1-1ubuntu0.1", row["deb-patched"]),
            "pypi": ("pkg:pypi/pyyaml@5.3.1", 52 + 44 * 2.5), "acme": ("pkg:pypi/pyyaml@5.3.1%2Bacme1", row["local-backport"]),
            "fixed": ("pkg:pypi/pyyaml@6.0.2", 52 + 44 * 6.5)}
    links = {"deb-unpatched": ["deb1", "pypi"], "deb-patched": ["deb2", "pypi"], "pypi": ["pypi"], "git": ["pypi"],
             "local": ["pypi"], "local-backport": ["acme"], "local-relabel": ["fixed"], "pypi-fixed": ["fixed"]}
    code = {"vuln": 52 + 44 * 2.5 - 28, "fix": 52 + 44 * 5 - 28}
    for v, y in row.items():
        for k in links[v]:
            hot = (v, k) in (("deb-patched", "pypi"), ("local-relabel", "fixed"))
            s.curve(cx, y + 16, lx + lw, left[k][1] + 16, CRIT if hot else MUTED, 2.4 if hot else 1.4)
        s.curve(cx + cw, y + 16, rx, code["vuln" if v in VULNERABLE else "fix"] + 44)
    for k, (purl, y) in left.items():
        shared = k in ("pypi", "fixed")
        s.rect(lx, y, lw, 32, CARD, CRIT if shared else AXIS, 7, 2 if shared else 1)
        s.text(lx + 10, y + 21, purl, 11, INK, 400, "start", MONO)
    s.text(lx, left["pypi"][1] + 50, "shared by 5 images: 4 vulnerable, 1 fixed", 12, INK2, 600)
    s.text(lx, left["fixed"][1] + 50, "shared by 2 images: 1 fixed, 1 vulnerable", 12, INK2, 600)
    for v, y in row.items():
        s.rect(cx, y, cw, 32, CARD, AXIS, 7)
        s.text(cx + cw / 2, y + 21, v, 13, INK, 600, "middle")
    for k, color, title, digest, note in (("vuln", CRIT, "vulnerable", "sha256 3b751a7f…", "exploit works"),
                                         ("fix", GOOD, "fixed", "sha256 90d8247d…", "exploit fails")):
        y = code[k]
        s.rect(rx, y, rw, 88, CARD, AXIS, 7)
        s.rect(rx, y, 7, 88, color, "none", 3)
        s.text(rx + 18, y + 23, title, 13.5, INK, 600)
        s.text(rx + 18, y + 42, "constructor.py", 12, INK2, 400, "start", MONO)
        s.text(rx + 18, y + 59, digest, 12, INK2)
        s.text(rx + 18, y + 76, note, 12, INK2)
    s.text(lx, 422, "Red links: fixed code named pkg:pypi/pyyaml@5.3.1 (deb-patched) and vulnerable code", 12, INK2)
    s.text(lx, 439, "named pkg:pypi/pyyaml@6.0.2 (local-relabel).", 12, INK2)
    s.save("sbom-vex-identities")


def verdicts():
    """Figure 2: the verdict of every SBOM generator -> vulnerability scanner pair on every image, in three modes."""
    x0, cw, ch, gap, pgap, top, pitch = 140, 44, 30, 3, 18, 70, 36
    pw = 4 * cw + 3 * gap
    bottom = top + pitch * len(VARIANTS)
    s = Svg(bottom + 96, "Verdicts for CVE-2020-14343 per image and SBOM generator→vulnerability scanner pair",
            "Three panels (without VEX, with --vex, with vexctl filter); rows are the images, columns the four "
            "SBOM generator → vulnerability scanner pairs. Cells show ✓ when the scan agrees with the oracle, "
            "FP or FN otherwise.")
    for i, v in enumerate(VARIANTS):
        y = top + i * pitch
        s.text(16, y + 13, v, 13, INK, 600)
        s.text(16, y + 27, "vulnerable" if v in VULNERABLE else "not vulnerable", 11, INK2)
    for k, (title, grid) in enumerate(VERDICTS.items()):
        px = x0 + k * (pw + pgap)
        s.text(px + pw / 2, 24, title, 13, INK, 600, "middle")
        for j, (a, b) in enumerate(PAIRS):
            mx = px + j * (cw + gap) + cw / 2
            s.text(mx, 44, a, 11, INK2, 400, "middle")
            s.text(mx, 58, "→" + b, 11, INK2, 400, "middle")
        wrong = 0
        for i, v in enumerate(VARIANTS):
            for j, cellv in enumerate(grid[v]):
                s.cell(px + j * (cw + gap), top + i * pitch, cw, ch, cellv)
                wrong += cellv in ("FP", "FN")
        s.text(px + pw / 2, bottom + 18, f"{wrong} of {4 * len(VARIANTS)} wrong", 13, INK, 600, "middle")
    y = bottom + 52
    for x, v, label in ((16, "ok", "agrees with the oracle"), (206, "FP", "reported, not vulnerable"),
                        (408, "FN", "vulnerable, not reported")):
        s.cell(x, y - 16, 26, 22, v)
        s.text(x + 33, y, label, 11.5, INK2)
    s.text(16, y + 24, "† the FP was removed by a statement whose product is the deb, not the PyPI component", 11.5, INK2)
    s.save("sbom-vex-verdicts")


if __name__ == "__main__":
    pipeline()
    verdicts()
    identities()
