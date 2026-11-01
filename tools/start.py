"""一键启动器：环境自检 → 数据准备 → 启动伦理熔断控制台。

用法
----
    python tools/start.py                  # 自检 + 启动服务 + 自动打开浏览器
    python tools/start.py --with-data      # 自检 + 生成数据/跑实验 + 启动服务
    python tools/start.py --check-only     # 只做环境自检，不启动
    python tools/start.py --port 9000      # 指定端口
    python tools/start.py --no-browser     # 不自动打开浏览器

Windows 下可直接双击 `启动项目.bat`。
"""
from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys
import time
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable

#: 启动必需（纯标准库）；缺失只影响部分功能
REQUIRED_MODULES = []
#: 实验与绘图需要（缺失时降级，不影响控制台本身）
OPTIONAL_MODULES = [
    ("numpy", "数值计算（实验与标定）"),
    ("pandas", "数据处理（实验汇总）"),
    ("matplotlib", "绘图（可选）"),
    ("yaml", "YAML 配置（PyYAML）"),
]

OK, WARN, BAD = "[ OK ]", "[WARN]", "[FAIL]"


def hr(title: str = "") -> None:
    if title:
        print(f"\n── {title} " + "─" * max(0, 62 - len(title)))
    else:
        print("─" * 68)


def check_python() -> bool:
    hr("运行环境")
    v = sys.version_info
    print(f"{OK} Python {v.major}.{v.minor}.{v.micro}  ({sys.executable})")
    if v < (3, 11):
        print(f"{BAD} 需要 Python 3.11+，当前 {v.major}.{v.minor}")
        return False
    return True


def check_modules() -> bool:
    import importlib.util

    missing_required = []
    for name in REQUIRED_MODULES:
        if importlib.util.find_spec(name) is None:
            missing_required.append(name)
    if missing_required:
        print(f"{BAD} 缺少必需模块：{', '.join(missing_required)}")
        return False
    for name, desc in OPTIONAL_MODULES:
        if importlib.util.find_spec(name) is None:
            print(f"{WARN} 未安装 {name}（{desc}）——控制台仍可启动，相关功能降级")
        else:
            print(f"{OK} {name}（{desc}）")
    return True


def check_project() -> bool:
    hr("项目文件")
    must = [
        "ethgate/__init__.py",
        "ethgate/types.py",
        "ethgate/taxonomy.py",
        "ethgate/server.py",
        "web/index.html",
        "web/app.js",
        "web/styles.css",
        "configs/gate.yaml",
    ]
    ok = True
    for rel in must:
        p = ROOT / rel
        if p.exists():
            print(f"{OK} {rel}")
        else:
            print(f"{BAD} 缺失 {rel}")
            ok = False
    return ok


def run_selfcheck() -> bool:
    hr("核心模块自检（AHP 一致性 / Kendall's W / 18 格矩阵）")
    r = subprocess.run(
        [PY, str(ROOT / "tools" / "selfcheck.py")],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    out = (r.stdout or "") + (r.stderr or "")
    for line in out.splitlines():
        if any(k in line for k in ("CR =", "一致性", "kendall_w", "高危格共", "通过", "未通过")):
            print("  " + line.strip())
    if r.returncode != 0:
        print(f"{WARN} 自检脚本返回码 {r.returncode}，继续启动")
    return True


def check_data() -> dict:
    hr("数据状态")
    ds = ROOT / "data" / "datasets"
    rs = ROOT / "data" / "results"
    state = {
        "datasets": sorted(p.stem for p in ds.glob("*.json")) if ds.exists() else [],
        "results": sorted(p.name for p in rs.glob("summary_*.json")) if rs.exists() else [],
        "audit": (ROOT / "data" / "audit" / "audit_chain.jsonl").exists(),
    }
    if state["datasets"]:
        print(f"{OK} 数据集：{', '.join(state['datasets'])}")
    else:
        print(f"{WARN} 没有数据集——仪表盘的「数据集」页会是空的")
    if state["results"]:
        print(f"{OK} 实验结果：{len(state['results'])} 份汇总")
    else:
        print(f"{WARN} 没有实验结果——帕累托前沿会是空的")
    if state["audit"]:
        print(f"{OK} 审计链文件存在")
    return state


def prepare_data(with_experiment: bool) -> None:
    hr("准备数据")
    ds = ROOT / "data" / "datasets"
    rs = ROOT / "data" / "results"
    if not (ds.exists() and list(ds.glob("*.json"))):
        print("生成两路危险修改样本集…", flush=True)
        for kind in ("artificial", "emergent"):
            subprocess.run(
                [PY, "-m", "ethgate.cli", "dataset", "--kind", kind,
                 "--out", str(ds / kind)],
                cwd=str(ROOT),
            )
    if with_experiment and not (rs.exists() and list(rs.glob("summary_*.json"))):
        print("跑对照实验（5 策略 × 3 任务集 × 2 样本来源 × 5 次重复，约需数分钟）…", flush=True)
        subprocess.run(
            [PY, "-m", "ethgate.cli", "experiment",
             "--strategies", "none,rule,classifier,llm_review,full",
             "--suites", "code,qa,tool", "--repeats", "5"],
            cwd=str(ROOT),
        )
    check_data()


def free_port(port: int) -> int:
    """端口被占用时自动往后找一个可用端口。"""
    for candidate in range(port, port + 20):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("127.0.0.1", candidate))
                return candidate
            except OSError:
                continue
    return port


def serve(port: int, open_browser: bool) -> int:
    hr("启动控制台")
    port = free_port(port)
    url = f"http://127.0.0.1:{port}"
    print(f"{OK} 控制台地址：{url}")
    print(f"{OK} 六个页面：总览 / 判定详情 / 风险矩阵 / 前沿与成本 / 数据集 / 审计链")
    print("   按 Ctrl+C 停止\n")

    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUNBUFFERED"] = "1"
    proc = subprocess.Popen(
        [PY, "-m", "ethgate.server", "--host", "127.0.0.1", "--port", str(port)],
        cwd=str(ROOT),
        env=env,
    )

    if open_browser:
        def _open() -> None:
            time.sleep(1.2)
            try:
                webbrowser.open(url)
            except Exception:
                pass
        import threading

        threading.Thread(target=_open, daemon=True).start()

    try:
        proc.wait()
    except KeyboardInterrupt:
        print("\n正在停止…")
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="伦理熔断原型 · 一键启动")
    ap.add_argument("--port", type=int, default=8000, help="服务端口（被占用时自动顺延）")
    ap.add_argument("--no-browser", action="store_true", help="不自动打开浏览器")
    ap.add_argument("--with-data", action="store_true",
                    help="启动前生成数据集并跑完整对照实验（数分钟）")
    ap.add_argument("--check-only", action="store_true", help="只做环境自检")
    args = ap.parse_args()

    print("=" * 68)
    print("  自进化智能体的伦理熔断机制 · 一键启动")
    print("  面向自我修改的准入控制与对齐成本测量")
    print("=" * 68)

    ok = check_python() and check_modules() and check_project()
    if not ok:
        print("\n环境检查未通过，请先解决上面的问题。")
        return 1

    run_selfcheck()
    check_data()

    if args.check_only:
        hr("完成")
        print("环境自检通过。去掉 --check-only 即可启动控制台。")
        return 0

    prepare_data(args.with_data)
    return serve(args.port, not args.no_browser)


if __name__ == "__main__":
    sys.exit(main())
