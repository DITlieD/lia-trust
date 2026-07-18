#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
export NO_PROXY='*' no_proxy='*'
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy || true
if [[ ! -x bench/harbor/.venv/bin/python ]]; then
  uv venv bench/harbor/.venv
  uv pip install --python bench/harbor/.venv/bin/python -r bench/harbor/requirements.txt
fi
bench/harbor/.venv/bin/python bench/harbor/scripts/build_lia_trust_v0.py
exec bench/harbor/.venv/bin/python bench/harbor/run_three_arm.py --concurrency 1 "$@"
