#!/usr/bin/env bash
#
# Render every Mermaid .mmd under a directory to SVG + high-resolution PNG.
#
# Usage:
#   ./render-all-pngs.sh <input-dir> [output-dir] [scale]
#
# Examples:
#   ./render-all-pngs.sh ./seg-comm-map            # -> ./seg-comm-map/png, 2x
#   ./render-all-pngs.sh ./seg-comm-map ./png 3    # 3x
#   ./render-all-pngs.sh ~/Downloads/output/dionysus/output ~/Downloads/png
#
# Requires mermaid-cli (mmdc) and a headless browser:
#   npm install -g @mermaid-js/mermaid-cli
#
# PNG rasterisation uses rsvg-convert when present (best for very wide charts),
# otherwise falls back to mmdc itself. The zoom is capped so no side exceeds
# 32000 px (rsvg-convert's hard limit; also keeps memory sane).

set -uo pipefail

IN="${1:-.}"
OUT="${2:-$IN/png}"
SCALE="${3:-2}"
MAXDIM=32000

if ! command -v mmdc >/dev/null 2>&1; then
  echo "error: mmdc not found. Install it with:" >&2
  echo "  npm install -g @mermaid-js/mermaid-cli" >&2
  exit 2
fi

mkdir -p "$OUT"
CFG="$(mktemp)"
trap 'rm -f "$CFG"' EXIT

# Headless Chrome in a container usually needs --no-sandbox. Prefer a system
# Chrome if one exists; otherwise mermaid-cli's bundled Chrome is used.
printf '{"args":["--no-sandbox","--disable-setuid-sandbox"]}\n' > "$CFG"
for c in chromium chromium-browser google-chrome google-chrome-stable; do
  if command -v "$c" >/dev/null 2>&1; then
    printf '{"executablePath":"%s","args":["--no-sandbox","--disable-setuid-sandbox"]}\n' \
      "$(command -v "$c")" > "$CFG"
    break
  fi
done

have_rsvg=0
command -v rsvg-convert >/dev/null 2>&1 && have_rsvg=1

total=0
failed=0
while IFS= read -r -d '' f; do
  rel="${f#"$IN"/}"
  base="${rel%.mmd}"
  sub="$OUT/$(dirname "$rel")"
  name="$(basename "$base")"
  mkdir -p "$sub"
  total=$((total + 1))
  printf '[%d] %s\n' "$total" "$rel"

  # 1) SVG first: always reliable, and resolution independent.
  if ! mmdc -i "$f" -o "$sub/$name.svg" -b white -p "$CFG" -q 2>/dev/null; then
    echo "    ! SVG failed: $rel" >&2
    failed=$((failed + 1))
    continue
  fi

  # 2) Natural size from the SVG viewBox.
  read -r W H < <(grep -oE 'viewBox="0 0 [0-9.]+ [0-9.]+"' "$sub/$name.svg" \
    | head -1 | sed -E 's/.*0 0 ([0-9.]+) ([0-9.]+)/\1 \2/')
  W=${W%%.*}; W=${W%%[!0-9]*}
  H=${H%%.*}; H=${H%%[!0-9]*}
  [ -z "${W:-}" ] && W=1600
  [ -z "${H:-}" ] && H=1200

  # 3) Effective zoom: requested scale, capped so the largest side <= MAXDIM.
  eff="$SCALE"
  maxdim=$W
  [ "$H" -gt "$maxdim" ] && maxdim=$H
  if [ "$maxdim" -gt 0 ]; then
    cap=$(awk -v m="$MAXDIM" -v d="$maxdim" 'BEGIN{printf "%.3f", m/d}')
    if awk -v e="$eff" -v c="$cap" 'BEGIN{exit !(e>c)}'; then
      eff="$cap"
    fi
  fi

  # 4) PNG.
  if [ "$have_rsvg" = 1 ]; then
    rsvg-convert -z "$eff" -o "$sub/$name.png" "$sub/$name.svg" \
      || { echo "    ! PNG failed: $rel" >&2; failed=$((failed + 1)); }
  else
    mmdc -i "$f" -o "$sub/$name.png" -b white -w "$W" -H "$H" -s "$eff" -p "$CFG" -q 2>/dev/null \
      || { echo "    ! PNG failed: $rel" >&2; failed=$((failed + 1)); }
  fi
done < <(find "$IN" -type f -name '*.mmd' -print0 | sort -z)

echo
echo "Rendered $((total - failed))/$total diagram(s) into: $OUT"
echo "  SVG + PNG, scale ${SCALE}x (capped at ${MAXDIM}px per side)"
[ "$failed" -gt 0 ] && exit 1
exit 0
