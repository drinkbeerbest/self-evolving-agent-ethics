"""导出真实拦截语料 + 标注一致性工作表（回应"数据集应用太少、拦截无依据"）。

产物
----
data/corpus/proposals.jsonl   全部去重提案（含扫描器命中与判定结果）
data/corpus/labeling_sheet.csv  人工标注工作表（三位组员独立填写 rater_1/2/3 列）
data/corpus/stats.json        语料统计

标注协议（三人独立，互不通气）
    每行根据 diff 与理由判断"这次自我修改是否危险"，dangerous / safe 二选一。
    填完后运行 python tools/labeling_kappa.py 计算 Fleiss' κ 与
    扫描器规则对人工多数意见的 precision / recall——
    这就是把"我们自己定义危险"变成"规则经三人独立标注验证"。
"""
from __future__ import annotations

import csv
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ethgate.scanner import scan  # noqa: E402
from ethgate.types import Modification  # noqa: E402

LIVE_DIR = ROOT / "data" / "live"
AUDIT = ROOT / "data" / "audit" / "audit_chain.jsonl"
OUT_DIR = ROOT / "data" / "corpus"
SHEET_ROWS = 100


def load_modification(d: dict) -> Modification:
    from ethgate.server import modification_from_dict

    return modification_from_dict(d)


def _structured_changes(mod: dict) -> str:
    """把权限面/约束面/提示面的结构化变更转成标注者可读的摘要。"""
    parts = []
    if mod.get("new_tools"):
        parts.append("新增工具: " + "、".join(mod["new_tools"]))
    if mod.get("new_syscalls"):
        parts.append("新增系统调用: " + "、".join(mod["new_syscalls"]))
    if mod.get("new_network_hosts"):
        parts.append("新增网络出口: " + "、".join(mod["new_network_hosts"]))
    if mod.get("removed_constraints"):
        parts.append("删除约束: " + "；".join(mod["removed_constraints"]))
    if mod.get("constraint_rewrites"):
        parts.append("改写约束: " + "；".join(f"{a} → {b}" for a, b in mod["constraint_rewrites"]))
    if mod.get("added_prompts"):
        parts.append("新增提示: " + "；".join(mod["added_prompts"]))
    if mod.get("removed_prompts"):
        parts.append("删除提示: " + "；".join(mod["removed_prompts"]))
    if mod.get("hardcode_detected"):
        parts.append("检出硬编码/用例特判")
    if mod.get("log_level_delta", 0) < 0:
        parts.append("日志级别下调")
    return "；".join(parts)


def _diff_from_files(mod: dict) -> str:
    """从序列化的 Modification.files 重建 diff 文本。"""
    parts = []
    for f in mod.get("files") or []:
        parts.append(f"--- {f.get('path', '')}")
        for l in f.get("removed") or []:
            parts.append(f"- {l}")
        for l in f.get("added") or []:
            parts.append(f"+ {l}")
    return "\n".join(parts)


def collect() -> list[dict]:
    """从直播会话事件流收集全部去重提案。"""
    out: dict[str, dict] = {}
    if LIVE_DIR.exists():
        for f in sorted(LIVE_DIR.glob("*.jsonl")):
            session = f.stem
            for line in f.read_text(encoding="utf-8").splitlines():
                try:
                    e = json.loads(line)
                except Exception:
                    continue
                mod = e.get("mod")
                if not mod:
                    continue
                mid = mod.get("mod_id") or ""
                if not mid or mid in out:
                    continue
                out[mid] = {
                    "mod_id": mid,
                    "session": session,
                    "gen": e.get("gen"),
                    "origin": "live-" + e.get("raw", {}).get("kind", "?"),
                    "title": mod.get("title", ""),
                    "rationale": mod.get("rationale", ""),
                    "layer": mod.get("layer", ""),
                    "autonomy": mod.get("autonomy", ""),
                    "diff": _diff_from_files(mod),
                    "changes": _structured_changes(mod),
                    "verdict": None,
                }
            # 第二遍：把判定结果挂回提案
            for line in f.read_text(encoding="utf-8").splitlines():
                try:
                    e = json.loads(line)
                except Exception:
                    continue
                if e.get("type") not in ("blocked", "applied"):
                    continue
                mid = (e.get("verdict") or {}).get("mod", {}).get("mod_id", "")
                if mid in out and out[mid]["verdict"] is None:
                    out[mid]["verdict"] = e["verdict"].get("action", "")
    return list(out.values())


def main() -> int:
    proposals = collect()
    for p in proposals:
        try:
            hits = scan(load_modification(json.loads(json.dumps(
                {"mod_id": p["mod_id"], "agent_id": "x", "round_index": p["gen"] or 0,
                 "layer": p["layer"], "autonomy": p["autonomy"], "title": p["title"],
                 "rationale": p["rationale"], "files": _diff_to_files(p["diff"]),
                 "base_commit": "", "created_at": 0, "source": "corpus"}))))
            p["scan_hits"] = [{"rule_id": h["rule_id"], "name": h["name"]} for h in hits]
            p["scanner_dangerous"] = bool(hits)
        except Exception:
            p["scan_hits"] = []
            p["scanner_dangerous"] = False

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    with (OUT_DIR / "proposals.jsonl").open("w", encoding="utf-8") as f:
        for p in proposals:
            f.write(json.dumps(p, ensure_ascii=False) + "\n")

    # 标注工作表：优先取有 diff 的提案，不足则重复抽样补足到 SHEET_ROWS
    with_diff = [p for p in proposals if p["diff"].strip()]
    rows = (with_diff * ((SHEET_ROWS // max(1, len(with_diff))) + 1))[:SHEET_ROWS]
    with (OUT_DIR / "labeling_sheet.csv").open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["id", "session", "gen", "layer", "title", "rationale",
                    "changes_and_diff", "scanner_label", "rater_1", "rater_2", "rater_3"])
        for i, p in enumerate(rows, 1):
            excerpt = p["changes"] or "（无结构化变更）"
            if p["diff"]:
                excerpt += "\n" + p["diff"]
            w.writerow([f"P{i:03d}", p["session"], p["gen"], p["layer"],
                        p["title"], p["rationale"][:120],
                        excerpt[:800],
                        "dangerous" if p["scanner_dangerous"] else "safe",
                        "", "", ""])

    n_blocked = sum(1 for p in proposals if p["verdict"] in ("拒绝", "上报"))
    stats = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M"),
        "sessions": len({p["session"] for p in proposals}),
        "unique_proposals": len(proposals),
        "intercepted": n_blocked,
        "with_diff": len(with_diff),
        "sheet_rows": len(rows),
        "scanner_dangerous": sum(1 for p in proposals if p["scanner_dangerous"]),
    }
    (OUT_DIR / "stats.json").write_text(
        json.dumps(stats, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(stats, ensure_ascii=False, indent=2))
    print("标注工作表已生成：请三位组员独立填写 rater_1/2/3 列后运行 tools/labeling_kappa.py")
    return 0


def _diff_to_files(diff: str) -> list[dict]:
    """把 diff 文本还原成 FileChange 兼容结构（扫描器只认增删行）。"""
    files = []
    cur: dict | None = None
    for ln in (diff or "").splitlines():
        if ln.startswith("--- "):
            cur = {"path": ln[4:], "added": [], "removed": []}
            files.append(cur)
        elif ln.startswith("+ ") and cur is not None:
            cur["added"].append(ln[2:])
        elif ln.startswith("- ") and cur is not None:
            cur["removed"].append(ln[2:])
    return files


if __name__ == "__main__":
    raise SystemExit(main())
