"""导出会话语料与独立盲标工作表，不重复补数、不展示机器判定。

每位标注者只领取 rater_N.csv，填写 label=dangerous/safe。
labeling_sheet.csv 为合并模板；机器标签只存在 proposals.jsonl，完成后通过稳定 ID 关联。
"""
from __future__ import annotations
import csv
import hashlib
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from ethgate.datasets import _mod_from_dict
from ethgate.scanner import scan

LIVE_DIR = ROOT / "data" / "live"
OUT_DIR = ROOT / "data" / "corpus"
RATERS = ("rater_1", "rater_2", "rater_3")
EVIDENCE_FIELDS = ("id", "layer", "title", "rationale", "context", "changes_and_diff")


def _structured_changes(mod: dict) -> str:
    """只呈现修改事实，不展示扫描器/门禁结论。"""
    parts = []
    for key, label in (("new_tools", "新增工具"), ("new_syscalls", "新增系统调用"),
                       ("new_network_hosts", "新增网络出口"), ("removed_constraints", "删除约束"),
                       ("added_constraints", "新增约束"), ("added_prompts", "新增提示"),
                       ("removed_prompts", "删除提示")):
        if mod.get(key):
            parts.append(label + ": " + "；".join(map(str, mod[key])))
    if mod.get("constraint_rewrites"):
        parts.append("改写约束: " + "；".join(f"{a} → {b}" for a, b in mod["constraint_rewrites"]))
    if mod.get("log_level_delta"):
        parts.append(f"日志级别变化: {mod['log_level_delta']}")
    return "；".join(parts)


def _diff_from_files(mod: dict) -> str:
    parts = []
    for item in mod.get("files") or []:
        parts.append(f"--- {item.get('path', '')}")
        parts.extend("- " + str(line) for line in item.get("removed") or [])
        parts.extend("+ " + str(line) for line in item.get("added") or [])
    return "\n".join(parts)


def annotation_row(proposal: dict) -> dict:
    """相同证据只标一次，ID 与行序、时间和机器结论无关。"""
    evidence = {
        "layer": proposal.get("layer", ""), "title": proposal.get("title", ""),
        "rationale": proposal.get("rationale", ""), "context": proposal.get("context", "未知"),
        "changes_and_diff": "\n".join(filter(None, [proposal.get("changes"), proposal.get("diff")])),
    }
    canonical = json.dumps(evidence, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return {"id": "P-" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:20], **evidence}


def collect(live_dir: Path = LIVE_DIR, previous: Path | None = None) -> list[dict]:
    """完整会话优先；原始流不随库分发时保留既有语料。"""
    out = {}
    if previous is not None and previous.exists():
        for line in previous.read_text(encoding="utf-8").splitlines():
            if line.strip():
                proposal = json.loads(line)
                out[proposal["mod_id"]] = proposal
    for path in sorted(live_dir.glob("*.jsonl")) if live_dir.exists() else []:
        events = []
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        start = next((e for e in events if e.get("type") == "session_start"), {})
        context = json.dumps({"preauthorized": start.get("preauthorized", []),
                              "initial_constraints": start.get("vitals", {}).get("constraints", []),
                              "context_available": bool(start)}, ensure_ascii=False)
        for event in events:
            mod = event.get("mod")
            if not isinstance(mod, dict) or not mod.get("mod_id"):
                continue
            mid = mod["mod_id"]
            out[mid] = {
                "mod_id": mid, "session": path.stem, "gen": event.get("gen"),
                "origin": "live-" + str(event.get("raw", {}).get("kind", "?")),
                "session_mode": start.get("mode", "unknown"), "model": start.get("model", ""),
                "title": mod.get("title", ""), "rationale": mod.get("rationale", ""),
                "layer": mod.get("layer", ""), "autonomy": mod.get("autonomy", ""),
                "diff": _diff_from_files(mod), "changes": _structured_changes(mod),
                "context": context, "modification": mod, "verdict": None,
            }
        for event in events:
            if event.get("type") not in ("blocked", "applied"):
                continue
            verdict = event.get("verdict") or {}
            mid = verdict.get("mod", {}).get("mod_id")
            if mid in out:
                out[mid]["verdict"] = verdict.get("action")
    return list(out.values())


def _read_labels(path: Path, columns: tuple[str, ...]) -> dict[str, dict]:
    if not path.exists():
        return {}
    with path.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    labels = {}
    for row in rows:
        values = {col: (row.get(col) or "").strip() for col in columns}
        if not any(values.values()):
            continue
        if not row.get("id", "").startswith("P-"):
            raise ValueError(f"{path.name} 含旧行号标注；请先按证据迁移，导出不会覆盖已填标签")
        if row["id"] in labels and labels[row["id"]] != values:
            raise ValueError(f"{path.name} 存在冲突的重复标注 ID")
        labels[row["id"]] = values
    return labels


def export_corpus(proposals: list[dict], out_dir: Path) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    labels = _read_labels(out_dir / "labeling_sheet.csv", RATERS)
    independent = {r: _read_labels(out_dir / f"{r}.csv", ("label",)) for r in RATERS}
    unique = {}
    for proposal in proposals:
        if proposal.get("modification"):
            try:
                hits = scan(_mod_from_dict(proposal["modification"]))
                proposal["scan_hits"] = [{"rule_id": h["rule_id"], "name": h["name"]} for h in hits]
                proposal["scanner_dangerous"] = bool(hits)
                proposal["scanner_evidence"] = "complete_modification"
            except (ValueError, TypeError, KeyError) as exc:
                proposal["scanner_dangerous"] = None
                proposal["scanner_evidence"] = f"unavailable: {type(exc).__name__}"
        else:
            proposal.setdefault("scanner_evidence", "legacy_export_incomplete_fields")
        proposal.setdefault("session_mode", "unknown")
        row = annotation_row(proposal)
        proposal["annotation_id"] = row["id"]
        if row["changes_and_diff"].strip():
            unique.setdefault(row["id"], row)
    rows = sorted(unique.values(), key=lambda row: row["id"])
    active_ids = set(unique)
    if any(set(saved) - active_ids for saved in [labels, *independent.values()]):
        raise ValueError("新语料缺少已填标注的稳定 ID；请先迁移，导出不会删除人工工作")
    for name, columns, saved in [("labeling_sheet", RATERS, labels),
                                 *((r, ("label",), independent[r]) for r in RATERS)]:
        with (out_dir / f"{name}.csv").open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=[*EVIDENCE_FIELDS, *columns])
            writer.writeheader()
            for row in rows:
                writer.writerow({**row, **saved.get(row["id"], {})})
    with (out_dir / "proposals.jsonl").open("w", encoding="utf-8", newline="\n") as handle:
        for proposal in proposals:
            handle.write(json.dumps(proposal, ensure_ascii=False) + "\n")
    stats = {
        "schema": "ethgate.corpus/v2", "generated_at": datetime.now(timezone.utc).isoformat(),
        "sessions": len({p["session"] for p in proposals}), "unique_proposals": len(proposals),
        "intercepted": sum(p.get("verdict") in ("拒绝", "上报") for p in proposals),
        "with_diff": sum(bool(p.get("diff", "").strip()) for p in proposals),
        "sheet_rows": len(rows), "repeated_padding": False, "blind_annotation": True,
        "scanner_dangerous": sum(p.get("scanner_dangerous") is True for p in proposals),
        "scanner_unknown": sum(p.get("scanner_dangerous") is None for p in proposals),
        "by_session_mode": dict(sorted(Counter(p["session_mode"] for p in proposals).items())),
        "human_validation": "pending; no labels are generated by this script",
    }
    (out_dir / "stats.json").write_text(json.dumps(stats, ensure_ascii=False, indent=2), encoding="utf-8", newline="\n")
    return stats


def main() -> int:
    stats = export_corpus(collect(previous=OUT_DIR / "proposals.jsonl"), OUT_DIR)
    print(json.dumps(stats, ensure_ascii=False, indent=2))
    print("三位组员各自领取 rater_N.csv 独立填写 label；完成后运行 tools/labeling_kappa.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
