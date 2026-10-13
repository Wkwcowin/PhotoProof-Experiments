#!/usr/bin/env bash
set -euo pipefail
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
result_dir="${1:-$repo_dir/runs/pixel-auth-$(date +%Y%m%d-%H%M%S)}"
case "$result_dir" in /*) ;; *) result_dir="$PWD/$result_dir" ;; esac
if [ -e "$result_dir" ]; then
  echo "结果目录已存在，请指定新目录：$result_dir" >&2
  exit 1
fi
mkdir -p "$repo_dir/.local/bin" "$(dirname "$result_dir")"
cd "$repo_dir/src"
go build -o "$repo_dir/.local/bin/pixelproof" ./cmd/pixelproof
proof_cli="$repo_dir/.local/bin/pixelproof"
"$proof_cli" -mode init -workspace "$result_dir" -input "$repo_dir/1.JPG"
"$proof_cli" -mode edit -workspace "$result_dir" -input "$repo_dir/1.JPG" -out "$result_dir/edit-a" -x 137 -y 83 -width 901 -height 617 -resize-width 451 -resize-height 309 -rotate 90
"$proof_cli" -mode edit -trusted "$result_dir/trusted" -prior "$result_dir/edit-a" -out "$result_dir/edit-b" -x 17 -y 29 -width 271 -height 397 -resize-width 181 -resize-height 265 -rotate 270
PHOTOPROOF_PIXEL_WORKSPACE="$result_dir" go test ./cmd/pixelproof -run TestRealPhotoChain -count=1 -v | tee "$result_dir/real-photo-tests.log"
mkdir "$result_dir/verification-only"
cp -R "$result_dir/trusted" "$result_dir/verification-only/trusted"
cp -R "$result_dir/edit-b" "$result_dir/verification-only/final-bundle"
"$proof_cli" -mode verify -trusted "$result_dir/verification-only/trusted" -bundle "$result_dir/verification-only/final-bundle" | tee "$result_dir/isolated-verification.log"
echo "完成。图片、证明和检查记录：$result_dir"
