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
PRIORITY_COLOR = {"P0": "#fa5252", "P1": "#f59f00", "P2": "#0ca678"}


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


# Linear/Vercel clean white style
CSS = """
:root{
  --bg:#ffffff;--bg-subtle:#fafafa;--border:#eaeaea;
  --text:#000000;--text-2:#666666;--text-3:#999999;
  --accent:#5e6ad2;--accent-soft:#eef0fd;
  --green:#0ca678;--green-bg:#e6fcf5;
  --yellow:#e8890c;--yellow-bg:#fff9db;
  --red:#fa5252;--red-bg:#ffe3e3;
  --gray:#868e96;--gray-bg:#f1f3f5;
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;
  background:var(--bg);color:var(--text);line-height:1.6;
  -webkit-font-smoothing:antialiased}
.page{max-width:1200px;margin:0 auto;padding:48px 24px 80px}
header.top{margin-bottom:40px}
header.top h1{font-size:28px;font-weight:700;letter-spacing:-0.02em;margin-bottom:8px}
header.top .meta{color:var(--text-3);font-size:13px}
section{margin-bottom:48px}
section>h2{font-size:15px;font-weight:600;color:var(--text-2);
  text-transform:uppercase;letter-spacing:0.08em;margin-bottom:16px;
  padding-bottom:12px;border-bottom:1px solid var(--border)}
.kanban{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}
.col{background:var(--bg-subtle);border:1px solid var(--border);border-radius:12px;padding:16px;min-height:120px}
.col h3{font-size:13px;font-weight:600;color:var(--text-2);margin-bottom:12px;
  display:flex;align-items:center;gap:8px}
.col h3 .count{display:inline-flex;align-items:center;justify-content:center;
  min-width:22px;height:22px;padding:0 6px;border-radius:11px;
  background:#fff;border:1px solid var(--border);font-size:12px;color:var(--text-2)}
.card{background:#fff;border:1px solid var(--border);border-radius:8px;
  padding:14px;margin-bottom:10px;transition:box-shadow .15s ease,border-color .15s ease}
.card:hover{box-shadow:0 4px 12px rgba(0,0,0,.06);border-color:#d4d4d4}
.card:last-child{margin-bottom:0}
.card .row1{display:flex;align-items:center;gap:8px;margin-bottom:6px}
.card .rid{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;
  color:var(--text-2);background:var(--gray-bg);padding:2px 8px;border-radius:4px}
.card .pri{font-size:11px;font-weight:700;padding:2px 8px;border-radius:4px}
.card .pri.P0{background:var(--red-bg);color:var(--red)}
.card .pri.P1{background:var(--yellow-bg);color:var(--yellow)}
.card .pri.P2{background:var(--green-bg);color:var(--green)}
.card .title{font-size:14px;font-weight:500;margin-bottom:6px}
.card .acc{font-size:12px;color:var(--text-3);line-height:1.5}
.empty{color:var(--text-3);text-align:center;padding:32px 16px;font-size:13px;
  border:1px dashed var(--border);border-radius:8px;background:#fff}
table{width:100%;border-collapse:collapse;font-size:13px;background:#fff;
  border:1px solid var(--border);border-radius:8px;overflow:hidden}
thead th{background:var(--bg-subtle);font-weight:600;color:var(--text-2);
  text-align:left;padding:10px 14px;border-bottom:1px solid var(--border);font-size:12px;
  text-transform:uppercase;letter-spacing:0.04em}
tbody td{padding:10px 14px;border-bottom:1px solid var(--border)}
tbody tr:last-child td{border-bottom:none}
tbody tr:hover{background:var(--bg-subtle)}
tbody tr.stale30{background:#fffdf5}
tbody tr.stale90{background:#fff8f8}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;
  background:var(--gray-bg);padding:2px 6px;border-radius:4px;color:var(--text-2)}
.timeline{position:relative;margin-left:6px;padding-left:24px}
.timeline::before{content:"";position:absolute;left:0;top:8px;bottom:8px;width:2px;background:var(--border)}
.tl-item{position:relative;margin-bottom:18px;font-size:13px}
.tl-item::before{content:"";position:absolute;left:-29px;top:6px;width:8px;height:8px;
  border-radius:50%;background:#fff;border:2px solid var(--accent)}
.tl-item .hash{font-family:ui-monospace,Menlo,monospace;color:var(--accent);font-size:12px;margin-right:8px}
.tl-item .meta{color:var(--text-3);font-size:12px;margin-left:8px}
.badge{display:inline-flex;align-items:center;gap:6px;padding:6px 14px;border-radius:999px;
  font-size:13px;font-weight:600}
.badge::before{content:"";width:8px;height:8px;border-radius:50%;background:currentColor}
.badge.green{background:var(--green-bg);color:var(--green)}
.badge.red{background:var(--red-bg);color:var(--red)}
.badge.gray{background:var(--gray-bg);color:var(--gray)}
.badge.yellow{background:var(--yellow-bg);color:var(--yellow)}
.charts{display:flex;gap:32px;flex-wrap:wrap;align-items:center;margin-bottom:20px}
.chart-card{background:#fff;border:1px solid var(--border);border-radius:12px;padding:20px}
.stat{font-size:14px;color:var(--text-2)}
.stat b{font-size:20px;color:var(--text);font-weight:700}
.stat .ok{color:var(--green)}.stat .fail{color:var(--red)}
.note{font-size:13px;color:var(--text-2);background:var(--accent-soft);
  border:1px solid #dfe3fa;border-radius:8px;padding:12px 16px;margin-top:12px}
.note.err{background:var(--red-bg);border-color:#ffc9c9;color:#c92a2a}
@media(max-width:720px){.kanban{grid-template-columns:1fr}.page{padding:32px 16px 64px}header.top h1{font-size:22px}}
"""


def pie_chart_js(canvas_id: str, counts: dict, colors: list[str]) -> str:
    labels = list(counts.keys())
    values = [counts[k] for k in labels]
    return f"""
(function(){{
var c=document.getElementById('{canvas_id}');if(!c)return;var x=c.getContext('2d');
var vals={json.dumps(values)},labs={json.dumps(labels)},cols={json.dumps(colors)};
var tot=vals.reduce((a,b)=>a+b,0);var cx=90,cy=90,r=70,a0=-Math.PI/2;
if(tot===0){{x.strokeStyle='#eaeaea';x.lineWidth=14;x.beginPath();x.arc(cx,cy,r-7,0,7);x.stroke();
x.fillStyle='#999';x.font='12px Inter,sans-serif';x.textAlign='center';x.fillText('暂无数据',cx,cy+4);return;}}
vals.forEach(function(v,i){{var a1=a0+v/tot*2*Math.PI;
x.strokeStyle=cols[i%cols.length];x.lineWidth=22;x.beginPath();x.arc(cx,cy,r-11,a0,a1);x.stroke();a0=a1;}});
var lx=190;x.font='13px Inter,sans-serif';
labs.forEach(function(l,i){{x.fillStyle=cols[i%cols.length];
x.beginPath();x.arc(lx+6,26+i*26,6,0,7);x.fill();
x.fillStyle='#666';x.textAlign='left';x.fillText(l+': '+vals[i],lx+20,30+i*26);}});
}})();"""


def donut_js(canvas_id: str, passed: int, failed: int) -> str:
    tot = passed + failed
    return f"""
(function(){{
var c=document.getElementById('{canvas_id}');if(!c)return;var x=c.getContext('2d');
var p={passed},f={failed},tot=p+f,cx=90,cy=90,r=70,ir=44;
if(tot===0){{x.strokeStyle='#eaeaea';x.lineWidth=r-ir;x.beginPath();x.arc(cx,cy,(r+ir)/2,0,7);x.stroke();
x.fillStyle='#999';x.font='12px Inter,sans-serif';x.textAlign='center';x.fillText('暂无数据',cx,cy+4);return;}}
var a0=-Math.PI/2,a1=a0+p/tot*2*Math.PI;
x.strokeStyle='#0ca678';x.lineWidth=r-ir;x.lineCap='round';
x.beginPath();x.arc(cx,cy,(r+ir)/2,a0,a1);x.stroke();
if(f>0){{x.strokeStyle='#fa5252';x.beginPath();x.arc(cx,cy,(r+ir)/2,a1,a0+2*Math.PI);x.stroke();}}
x.fillStyle='#000';x.font='700 18px Inter,sans-serif';x.textAlign='center';
x.fillText(Math.round(p/tot*100)+'%',cx,cy+7);
}})();"""


def esc(s) -> str:
    return html.escape(str(s))


def render(reqs, docs, commits, test_data, test_err, build_data, build_err,
           gen_time: str, degraded_msg: str | None = None) -> str:
    scripts: list[str] = []
    body: list[str] = []
    body.append("<header class='top'><h1>nexus-web-gateway</h1>"
                f"<div class='meta'>开发状态看板 · 更新于 {esc(gen_time)} UTC</div></header>")

    if degraded_msg is not None:
        # Degraded mode: F5 red + error explanation only (SPEC §2 F5)
        body.append("<section><h2>构建状态</h2>")
        body.append("<span class='badge red'>构建失败</span>")
        body.append(f"<div class='note err'>{esc(degraded_msg)}</div>")
        body.append("<p class='meta' style='margin-top:12px;font-size:12px;color:#999'>"
                    "降级页面：仅显示构建状态，其余功能因 requirements.toml 校验失败暂不可用。</p></section>")
    else:
        # F1: requirements kanban
        body.append("<section><h2>需求看板</h2>")
        if reqs is None:
            body.append("<p class='empty'>暂无数据（requirements.toml 不存在）</p>")
        else:
            counts = {s: 0 for s in STATUSES}
            for r in reqs:
                counts[r["status"]] = counts.get(r["status"], 0) + 1
            body.append("<div class='charts'><div class='chart-card'>"
                        "<canvas id='pie1' width='340' height='180'></canvas></div></div>")
            scripts.append(pie_chart_js("pie1", {STATUS_LABEL[k]: counts[k] for k in STATUSES},
                                        ["#dee2e6", "#ffd43b", "#0ca678"]))
            body.append("<div class='kanban'>")
            for s in STATUSES:
                items = [r for r in reqs if r["status"] == s]
                body.append(f"<div class='col'><h3>{STATUS_LABEL[s]}"
                            f"<span class='count'>{len(items)}</span></h3>")
                if not items:
                    body.append("<p class='empty'>暂无</p>")
                for r in items:
                    body.append(
                        f"<div class='card'>"
                        f"<div class='row1'><span class='rid'>{esc(r['id'])}</span>"
                        f"<span class='pri {esc(r['priority'])}'>{esc(r['priority'])}</span></div>"
                        f"<div class='title'>{esc(r['title'])}</div>"
                        f"<div class='acc'>{esc(r['acceptance'])}</div></div>"
                    )
                body.append("</div>")
            body.append("</div>")
        body.append("</section>")

        # F2: docs
        body.append("<section><h2>文档状态</h2>")
        if not docs:
            body.append("<p class='empty'>暂无文档（docs/ 为空）</p>")
        else:
            body.append("<table><thead><tr><th>文件</th><th>最后修改</th><th>Commit</th><th>天数</th></tr></thead><tbody>")
            for d in docs:
                stale_tag = ""
                if d['stale'] == 'stale90':
                    stale_tag = " <span class='badge red' style='font-size:11px;padding:2px 8px'>90天+</span>"
                elif d['stale'] == 'stale30':
                    stale_tag = " <span class='badge yellow' style='font-size:11px;padding:2px 8px'>30天+</span>"
                body.append(
                    f"<tr class='{d['stale']}'><td>{esc(d['name'])}{stale_tag}</td>"
                    f"<td>{esc(d['date'])}</td><td><code>{esc(d['commit'])}</code></td>"
                    f"<td>{d['age_days']}</td></tr>"
                )
            body.append("</tbody></table>")
        body.append("</section>")

        # F3: commits
        body.append("<section><h2>最近变更</h2>")
        if not commits:
            body.append("<p class='empty'>暂无 commit 记录</p>")
        else:
            body.append("<div class='timeline'>")
            for c in commits:
                body.append(
                    f"<div class='tl-item'><span class='hash'>{esc(c['hash'])}</span>"
                    f"{esc(c['subject'])}<span class='meta'>{esc(c['date'])} · {esc(c['author'])}</span></div>"
                )
            body.append("</div>")
        body.append("</section>")

        # F4: tests
        body.append("<section><h2>测试状态</h2>")
        if test_err == "missing":
            body.append("<p class='empty'>暂无数据</p>")
        elif test_err == "bad":
            body.append("<div class='note err'>数据错误（test-results.json 格式非法）</div>")
        else:
            p, f = int(test_data.get("passed", 0)), int(test_data.get("failed", 0))
            body.append("<div class='charts'><div class='chart-card'>"
                        f"<canvas id='donut1' width='200' height='180'></canvas></div>"
                        f"<div class='stat'>通过 <b class='ok'>{p}</b> &nbsp;·&nbsp; "
                        f"失败 <b class='fail'>{f}</b></div></div>")
            scripts.append(donut_js("donut1", p, f))
        body.append("</section>")

        # F5: build
        body.append("<section><h2>构建状态</h2>")
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
        body.append("</section>")

    return ("<!DOCTYPE html><html lang='zh-CN'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<title>nexus-web-gateway · 开发状态看板</title>"
            f"<style>{CSS}</style></head><body><div class='page'>"
            + "".join(body)
            + "</div><script>" + "".join(scripts) + "</script></body></html>")


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
