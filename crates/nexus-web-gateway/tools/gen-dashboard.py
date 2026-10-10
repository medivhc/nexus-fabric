#!/usr/bin/env python3
"""Generate gateway-dashboard index.html from git data.

Usage:
    python3 gen-dashboard.py [--degraded "error message"]
        [--test-results path] [--build-status path]
        [--out path] [--repo-root path]

Modes:
    normal   - full dashboard (F1-F5). requirements.toml invalid -> exit 1.
    degraded - minimal page: F5 red badge + error explanation only.
               Used when validate-requirements failed (test job skipped).

Only Python standard library (tomllib, json, subprocess, html, datetime).
Output: single self-contained index.html (inline CSS/JS, native Canvas).
"""
import argparse
import html
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

STATUSES = ["todo", "doing", "done"]
STATUS_LABEL = {"todo": "待做", "doing": "进行中", "done": "已完成"}
PRIORITY_COLOR = {"P0": "#e74c3c", "P1": "#f39c12", "P2": "#27ae60"}


def sh(cmd: list[str], cwd: Path) -> str:
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=30)
    return r.stdout.strip() if r.returncode == 0 else ""


def load_requirements(crate_dir: Path) -> tuple[list[dict] | None, str | None]:
    """Return (reqs, error). None reqs + None error = file missing (graceful)."""
    p = crate_dir / "requirements.toml"
    if not p.exists():
        return None, None
    try:
        import tomllib
        with open(p, "rb") as f:
            data = tomllib.load(f)
        reqs = data.get("req", [])
        # Light re-validation (CI already validated; fail-closed on parse error)
        for r in reqs:
            if r.get("status") not in ("todo", "doing", "done"):
                return None, f"invalid status in {r.get('id')}"
            if r.get("priority") not in ("P0", "P1", "P2"):
                return None, f"invalid priority in {r.get('id')}"
        return reqs, None
    except Exception as e:
        return None, f"parse error: {e}"


def load_docs(crate_dir: Path, repo_root: Path, now: datetime) -> list[dict]:
    docs_dir = crate_dir / "docs"
    out: list[dict] = []
    if not docs_dir.is_dir():
        return out
    for md in sorted(docs_dir.glob("*.md")):
        rel = md.relative_to(repo_root).as_posix()
        log = sh(
            ["git", "log", "-1", "--format=%H%x1f%ci", "--", rel], cwd=repo_root
        )
        if not log:
            continue  # untracked: skip (SPEC §2 F2)
        parts = log.split("\x1f")
        commit, datestr = parts[0], parts[1] if len(parts) > 1 else ""
        try:
            ctime = datetime.fromisoformat(datestr)
            if ctime.tzinfo is None:
                ctime = ctime.replace(tzinfo=timezone.utc)
            age_days = (now - ctime).days
        except Exception:
            age_days = -1
        if age_days > 90:
            stale = "stale90"
        elif age_days > 30:
            stale = "stale30"
        else:
            stale = "fresh"
        out.append({
            "name": md.name, "commit": commit[:7], "date": datestr[:10],
            "age_days": age_days, "stale": stale,
        })
    return out


def load_commits(crate_dir: Path, repo_root: Path) -> list[dict]:
    rel = crate_dir.relative_to(repo_root).as_posix()
    log = sh(
        ["git", "log", "--format=%H%x1f%s%x1f%ci%x1f%an", "-20", "--", rel],
        cwd=repo_root,
    )
    out: list[dict] = []
    for line in log.splitlines():
        parts = line.split("\x1f")
        if len(parts) < 4:
            continue
        out.append({
            "hash": parts[0][:7], "subject": parts[1],
            "date": parts[2][:10], "author": parts[3],
        })
    return out


def load_json_file(p: Path | None) -> tuple[dict | None, str | None]:
    """Return (data, error_kind). error_kind: None | 'missing' | 'bad'."""
    if p is None or not p.exists():
        return None, "missing"
    try:
        with open(p) as f:
            return json.load(f), None
    except Exception:
        return None, "bad"


CSS = """
*{box-sizing:border-box}body{font-family:system-ui,-apple-system,sans-serif;margin:0;padding:16px;background:#f5f7fa;color:#222}
h1{font-size:1.4em}h2{font-size:1.1em;border-bottom:2px solid #ddd;padding-bottom:4px}
.kanban{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}
.col{background:#fff;border-radius:8px;padding:10px;min-height:80px}
.card{background:#fafafa;border-left:4px solid #999;border-radius:4px;padding:8px;margin:6px 0;font-size:.9em}
.card .pri{font-weight:bold}.card .acc{color:#555;font-size:.85em;margin-top:4px}
.empty{color:#999;text-align:center;padding:20px}
table{width:100%;border-collapse:collapse;font-size:.9em;background:#fff}
th,td{padding:6px 8px;border-bottom:1px solid #eee;text-align:left}
tr.stale30{background:#fef9e7}tr.stale90{background:#fdedec}
.timeline{border-left:3px solid #3498db;margin-left:8px;padding-left:16px}
.tl-item{margin:10px 0;font-size:.9em}.tl-item .hash{font-family:monospace;color:#666}
.badge{display:inline-block;padding:6px 14px;border-radius:20px;color:#fff;font-weight:bold}
.badge.green{background:#27ae60}.badge.red{background:#e74c3c}.badge.gray{background:#95a5a6}
.charts{display:flex;gap:24px;flex-wrap:wrap;align-items:center}
canvas{background:#fff;border-radius:8px}
.meta{color:#888;font-size:.8em}
@media(max-width:600px){.kanban{grid-template-columns:1fr}table{font-size:.8em}}
"""


def pie_chart_js(canvas_id: str, counts: dict, colors: list[str]) -> str:
    labels = list(counts.keys())
    values = [counts[k] for k in labels]
    return f"""
(function(){{
var c=document.getElementById('{canvas_id}');if(!c)return;var x=c.getContext('2d');
var vals={json.dumps(values)},labs={json.dumps(labels)},cols={json.dumps(colors)};
var tot=vals.reduce((a,b)=>a+b,0);var cx=90,cy=90,r=70,a0=-Math.PI/2;
if(tot===0){{x.fillStyle='#95a5a6';x.beginPath();x.arc(cx,cy,r,0,7);x.fill();
x.fillStyle='#fff';x.font='12px sans-serif';x.textAlign='center';x.fillText('暂无数据',cx,cy);return;}}
vals.forEach(function(v,i){{var a1=a0+v/tot*2*Math.PI;
x.fillStyle=cols[i%cols.length];x.beginPath();x.moveTo(cx,cy);x.arc(cx,cy,r,a0,a1);x.closePath();x.fill();a0=a1;}});
var lx=180;x.font='12px sans-serif';
labs.forEach(function(l,i){{x.fillStyle=cols[i%cols.length];x.fillRect(lx,20+i*22,12,12);
x.fillStyle='#222';x.fillText(l+': '+vals[i],lx+18,30+i*22);}});
}})();"""


def donut_js(canvas_id: str, passed: int, failed: int) -> str:
    tot = passed + failed
    return f"""
(function(){{
var c=document.getElementById('{canvas_id}');if(!c)return;var x=c.getContext('2d');
var p={passed},f={failed},tot=p+f,cx=90,cy=90,r=70,ir=40;
if(tot===0){{x.strokeStyle='#95a5a6';x.lineWidth=r-ir;x.beginPath();x.arc(cx,cy,(r+ir)/2,0,7);x.stroke();
x.fillStyle='#888';x.font='12px sans-serif';x.textAlign='center';x.fillText('暂无数据',cx,cy+4);return;}}
var a0=-Math.PI/2,a1=a0+p/tot*2*Math.PI;
x.strokeStyle='#27ae60';x.lineWidth=r-ir;x.beginPath();x.arc(cx,cy,(r+ir)/2,a0,a1);x.stroke();
x.strokeStyle='#e74c3c';x.beginPath();x.arc(cx,cy,(r+ir)/2,a1,a0+2*Math.PI);x.stroke();
x.fillStyle='#222';x.font='bold 16px sans-serif';x.textAlign='center';
x.fillText(Math.round(p/tot*100)+'%',cx,cy+6);
}})();"""


def esc(s) -> str:
    return html.escape(str(s))


def render(reqs, docs, commits, test_data, test_err, build_data, build_err,
           gen_time: str, degraded_msg: str | None = None) -> str:
    scripts: list[str] = []
    body: list[str] = []
    body.append(f"<h1>nexus-web-gateway 开发状态看板</h1><p class='meta'>生成时间：{esc(gen_time)}（UTC）</p>")

    if degraded_msg is not None:
        # Degraded mode: F5 red + error explanation only (SPEC §2 F5)
        body.append("<h2>构建状态</h2>")
        body.append("<span class='badge red'>构建失败</span> <span style='color:#e74c3c'>前置校验失败</span>")
        body.append(f"<p>{esc(degraded_msg)}</p>")
        body.append("<p class='meta'>降级页面：仅显示构建状态，其余功能因 requirements.toml 校验失败暂不可用。</p>")
    else:
        # F1: requirements kanban
        body.append("<h2>需求看板</h2>")
        if reqs is None:
            body.append("<p class='empty'>暂无数据（requirements.toml 不存在）</p>")
        else:
            counts = {s: 0 for s in STATUSES}
            for r in reqs:
                counts[r["status"]] = counts.get(r["status"], 0) + 1
            body.append("<div class='charts'><canvas id='pie1' width='320' height='180'></canvas></div>")
            scripts.append(pie_chart_js("pie1", {STATUS_LABEL[k]: counts[k] for k in STATUSES},
                                        ["#95a5a6", "#f39c12", "#27ae60"]))
            body.append("<div class='kanban'>")
            for s in STATUSES:
                body.append(f"<div class='col'><h3>{STATUS_LABEL[s]}</h3>")
                items = [r for r in reqs if r["status"] == s]
                if not items:
                    body.append("<p class='empty'>暂无</p>")
                for r in items:
                    pc = PRIORITY_COLOR.get(r["priority"], "#999")
                    body.append(
                        f"<div class='card' style='border-left-color:{pc}'>"
                        f"<div><b>{esc(r['id'])}</b> <span class='pri' style='color:{pc}'>{esc(r['priority'])}</span></div>"
                        f"<div>{esc(r['title'])}</div>"
                        f"<div class='acc'>验收：{esc(r['acceptance'])}</div></div>"
                    )
                body.append("</div>")
            body.append("</div>")

        # F2: docs
        body.append("<h2>文档状态</h2>")
        if not docs:
            body.append("<p class='empty'>暂无文档（docs/ 为空）</p>")
        else:
            body.append("<table><tr><th>文件</th><th>最后修改</th><th>Commit</th><th>天数</th></tr>")
            for d in docs:
                body.append(
                    f"<tr class='{d['stale']}'><td>{esc(d['name'])}</td>"
                    f"<td>{esc(d['date'])}</td><td><code>{esc(d['commit'])}</code></td>"
                    f"<td>{d['age_days']}</td></tr>"
                )
            body.append("</table>")

        # F3: commits
        body.append("<h2>最近变更</h2>")
        if not commits:
            body.append("<p class='empty'>暂无 commit 记录</p>")
        else:
            body.append("<div class='timeline'>")
            for c in commits:
                body.append(
                    f"<div class='tl-item'><span class='hash'>{esc(c['hash'])}</span> "
                    f"{esc(c['subject'])} <span class='meta'>{esc(c['date'])} · {esc(c['author'])}</span></div>"
                )
            body.append("</div>")

        # F4: tests
        body.append("<h2>测试状态</h2>")
        if test_err == "missing":
            body.append("<p class='empty'>暂无数据</p>")
        elif test_err == "bad":
            body.append("<p style='color:#e74c3c'>数据错误（test-results.json 格式非法）</p>")
        else:
            p, f = int(test_data.get("passed", 0)), int(test_data.get("failed", 0))
            body.append(f"<div class='charts'><canvas id='donut1' width='200' height='180'></canvas>"
                        f"<div>通过 <b>{p}</b> · 失败 <b>{f}</b></div></div>")
            scripts.append(donut_js("donut1", p, f))

        # F5: build
        body.append("<h2>构建状态</h2>")
        if build_err == "missing":
            body.append("<span class='badge gray'>暂无数据</span>")
        elif build_err == "bad":
            body.append("<span class='badge red'>数据错误</span>")
        else:
            st = build_data.get("status")
            if st == "success":
                body.append("<span class='badge green'>构建成功</span>")
            else:
                body.append("<span class='badge red'>构建失败</span>")

    return ("<!DOCTYPE html><html lang='zh-CN'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>gateway-dashboard</title><style>{CSS}</style></head><body>"
            + "".join(body)
            + "<script>" + "".join(scripts) + "</script></body></html>")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--degraded", default=None, help="degraded mode error message")
    ap.add_argument("--test-results", default=None)
    ap.add_argument("--build-status", default=None)
    ap.add_argument("--out", default="index.html")
    ap.add_argument("--repo-root", default=None)
    ap.add_argument("--crate-dir", default=None)
    args = ap.parse_args()

    script_dir = Path(__file__).resolve().parent
    crate_dir = Path(args.crate_dir) if args.crate_dir else script_dir.parent
    repo_root = Path(args.repo_root) if args.repo_root else Path(
        sh(["git", "rev-parse", "--show-toplevel"], cwd=crate_dir) or str(crate_dir)
    )
    now = datetime.now(timezone.utc)
    gen_time = now.strftime("%Y-%m-%d %H:%M:%S")

    if args.degraded is not None:
        html_out = render(None, [], [], None, "missing", None, "missing",
                          gen_time, degraded_msg=args.degraded)
        Path(args.out).write_text(html_out, encoding="utf-8")
        print(f"degraded page written to {args.out}")
        return 0

    reqs, req_err = load_requirements(crate_dir)
    if req_err is not None:
        # fail-closed (SPEC §5.1): invalid requirements -> exit 1, no HTML
        print(f"ERROR: requirements.toml invalid: {req_err}", file=sys.stderr)
        return 1

    docs = load_docs(crate_dir, repo_root, now)
    commits = load_commits(crate_dir, repo_root)
    test_data, test_err = load_json_file(Path(args.test_results) if args.test_results else None)
    build_data, build_err = load_json_file(Path(args.build_status) if args.build_status else None)

    html_out = render(reqs, docs, commits, test_data, test_err,
                      build_data, build_err, gen_time)
    Path(args.out).write_text(html_out, encoding="utf-8")
    print(f"dashboard written to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
