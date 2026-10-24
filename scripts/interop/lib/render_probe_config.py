#!/usr/bin/env python3
"""渲染 probe 模板（token → 具体值）。凭据只从 secrets.env 读取。

ANYTLS_PADDING_MD5 由 crate 的 DEFAULT_PADDING_SCHEME 常量现算，避免脚本手写 md5 漂移
（probe 侧 validate_config 会再次断言，漂移 → 退出码 2）。
"""
import argparse
import hashlib
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
ANYTLS_SRC = REPO / "crates/nexus-outbound-anytls/src/lib.rs"


def padding_scheme_text():
    text = ANYTLS_SRC.read_text(encoding="utf-8")
    marker = 'DEFAULT_PADDING_SCHEME: &str = "\\'
    start = text.index(marker) + len(marker)
    end = text.index('";', start)
    raw = text[start:end]
    # Rust 行尾 `\` 只吃掉紧跟的换行；后续换行保留。
    if raw.startswith("\n"):
        raw = raw[1:]
    return raw


def load_secrets(path):
    values = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip()
    return values


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--template", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--run-dir", required=True)
    args = ap.parse_args()
    secrets = load_secrets(Path(args.run_dir) / "secrets.env")
    tokens = dict(secrets)
    tokens["ANYTLS_PADDING_MD5"] = hashlib.md5(
        padding_scheme_text().encode("utf-8")
    ).hexdigest()
    tokens["RUN_DIR"] = args.run_dir

    text = Path(args.template).read_text(encoding="utf-8")

    def sub(match):
        key = match.group(1)
        if key not in tokens:
            raise SystemExit(f"{args.template}: unknown token ${{{key}}}")
        value = tokens[key]
        if value == "":
            raise SystemExit(f"{args.template}: empty token ${{{key}}}")
        return value

    rendered = re.sub(r"\$\{([A-Z0-9_]+)\}", sub, text)
    if "${" in rendered:
        raise SystemExit(f"{args.template}: unresolved token remains")
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(rendered, encoding="utf-8")
    print(f"rendered {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
