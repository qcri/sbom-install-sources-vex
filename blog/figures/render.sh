#!/bin/sh
# Render figures/svg/*.svg to 2x PNG in assets/img/blog/2026/ with librsvg, in a throwaway Alpine container.
# usage: blog/figures/render.sh            (ENGINE=docker blog/figures/render.sh on a Docker host)
set -eu
cd "$(dirname "$0")/.."
ENGINE=${ENGINE:-podman}
OWNER=""
if [ "$ENGINE" = docker ]; then OWNER="$(id -u):$(id -g)"; fi   # rootful Docker would leave root-owned files
mkdir -p assets/img/blog/2026
"$ENGINE" run --rm -e OWNER="$OWNER" -v "$PWD:/w:Z" docker.io/library/alpine:3.20 sh -c '
  set -eu
  apk add -q --no-cache rsvg-convert font-noto font-dejavu >/dev/null
  for f in /w/figures/svg/*.svg; do
    out=/w/assets/img/blog/2026/$(basename "${f%.svg}").png
    rsvg-convert --zoom 2 --background-color "#fcfcfb" -o "$out" "$f"
    if [ -n "$OWNER" ]; then chown "$OWNER" "$out"; fi
    echo "rendered $out"
  done'
