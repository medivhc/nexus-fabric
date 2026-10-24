#!/usr/bin/env bash
# 渲染 docs/protocols/interop/ref-config/*.template.json -> $RUN_DIR/evidence/ref-config/<variant>.json
# 令牌替换只认白名单变量；任何未解析的 ${...} 残留 => 失败（不静默产出半渲染配置）。
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUN_DIR="${RUN_DIR:?RUN_DIR required}"
OUT_DIR="$RUN_DIR/evidence/ref-config"
TPL_DIR="$REPO_ROOT/docs/protocols/interop/ref-config"
SECRETS="$RUN_DIR/secrets.env"

[[ -f "$SECRETS" ]] || { echo "missing $SECRETS" >&2; exit 1; }
# shellcheck disable=SC1090
set -a; . "$SECRETS"; set +a
export RUN_DIR VLESS_UUID ANYTLS_PASSWORD HY2_PASSWORD HY2_OBFS_PASSWORD TROJAN_PASSWORD SS_PASSWORD

mkdir -p "$OUT_DIR"
render() {
  local tpl="$1" out="$2"
  python3 - "$tpl" "$out" <<'PY'
import os, re, sys
tpl, out = sys.argv[1], sys.argv[2]
text = open(tpl, encoding="utf-8").read()
allowed = {"RUN_DIR","VLESS_UUID","ANYTLS_PASSWORD","HY2_PASSWORD","HY2_OBFS_PASSWORD","TROJAN_PASSWORD","SS_PASSWORD"}
def sub(m):
    k = m.group(1)
    if k not in allowed:
        raise SystemExit(f"template {tpl}: unknown token ${{{k}}}")
    v = os.environ.get(k)
    if not v:
        raise SystemExit(f"template {tpl}: empty value for ${{{k}}}")
    return v
rendered = re.sub(r"\$\{([A-Z0-9_]+)\}", sub, text)
if "${" in rendered:
    raise SystemExit(f"template {tpl}: unresolved token remains")
open(out, "w", encoding="utf-8").write(rendered)
PY
}

count=0
for tpl in "$TPL_DIR"/*.template.json; do
  name="$(basename "$tpl" .template.json)"
  out="$OUT_DIR/$name.json"
  render "$tpl" "$out"
  sha256sum "$out" | awk '{print $1}' > "$out.sha256"
  count=$((count+1))
done
echo "rendered=$count out=$OUT_DIR"
