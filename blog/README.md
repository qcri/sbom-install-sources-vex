# Blog draft: robustness of SBOM and VEX tools

A draft post about this experiment for an al-folio (Jekyll) site. It is not part of the experiment pipeline.

## Layout

The folders mirror the site, so publishing is a copy:

| here | in the site repository |
|---|---|
| `_posts/2026-10-13-sbom-vex-robustness.md` | `_posts/` |
| `assets/img/blog/2026/sbom-vex-*.png` | `assets/img/blog/2026/` |

`figures/` holds the sources of the figures and is not copied.

## Figures

```bash
python3 -I blog/figures/make_figures.py      # writes blog/figures/svg/*.svg (standard library only)
blog/figures/render.sh                       # 2x PNGs with librsvg in an Alpine container (podman)
ENGINE=docker blog/figures/render.sh         # same, on a Docker host
```

- **Data.** The data is embedded in `make_figures.py`, so the script also works in the site repository. Each data block names its source in this repository: `out/results.json` of the 2026-10-08 run, and the probes in `out/probe/probes.txt` (PR #6).
- **Colour.** Verdict cells use two classes, each with a text label (✓, FP, FN), so meaning never rests on colour alone. The pale green wash and the red are separable for colour-blind readers (ΔE 34.7 deuteranopia, checked with a palette validator).
- **Background and text.** Figures use a light surface, because a PNG cannot follow the site's dark-mode toggle. Every chart has a table with the same data in the post.

## Compatibility

Checked on 2026-10-13 by adding the post to a clone of the site and building it with the site's own setup: `ruby:3.3.5-slim`, the steps of `bin/docker-entrypoint-local.sh`, and `jekyll build`. The build had no errors or warnings, and the rendered page was inspected in a browser. The prebuilt `amirpourmand/al-folio:slim` image of `docker-compose-slim.yml` did not start, because its bundler fails on that image's Ruby 4.0; this is unrelated to the post.

- **Front matter.** It matches the existing posts, plus `toc: beginning: true`, which puts the table of contents above the post. A sidebar TOC (`toc: sidebar: left`) also works, but it narrows the column to about 690 px, which makes the figures' labels small.
- **Figures.** They use `figure.liquid` as the other posts do. Captions are `<div class="caption" markdown="1">` blocks.
- **Liquid.** There are no `{{ }}` or `{% %}` anywhere except the figure includes. Code snippets that contain them would need `{% raw %}`.
- **MathJax.** There is no `$` outside code, so MathJax cannot misread prose.
- **Footnotes.** The two CISA quotes use kramdown footnotes.

## Before publishing

- **Repository visibility.** The post links https://github.com/JK-code505/sbom-install-sources-vex (in "Reproduce it" and "Credits"). Make the repository public before publishing, or readers will get a 404.
- **Date.** Check the date in the file name and the front matter.
- **Dependencies on PRs #6 and #8.** Findings 1–5 follow the corrected results in PR #6; Finding 6 uses probe 4.6 from PR #8. If either PR changes, update the post to match.
